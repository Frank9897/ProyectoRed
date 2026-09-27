using PacketDotNet;
using PacketDotNet.Lldp;
using ProyectoRed.Web.Models;
using SharpPcap;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ProyectoRed.Web.Services;

public class CapturadorPaquetesService
{
    public async Task<DispositivoDetectado> CapturarAsync(
        string nombreInterfaz)
    {
        CaptureDeviceList dispositivos =
            CaptureDeviceList.Instance;

        NetworkInterface interfazRed =
            NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(interfaz =>
                    string.Equals(
                        interfaz.Name,
                        nombreInterfaz,
                        StringComparison.OrdinalIgnoreCase));

        if (interfazRed == null)
        {
            throw new InvalidOperationException(
                $"No se encontró la interfaz de red '{nombreInterfaz}'.");
        }

        ICaptureDevice dispositivoSeleccionado = null;

        foreach (var dispositivo in dispositivos)
        {
            // En Windows, SharpPcap utiliza el formato:
            // \Device\NPF_{GUID}
            // Ese GUID corresponde al NetworkInterface.Id de .NET.
            if (string.Equals(
                    dispositivo.Name,
                    nombreInterfaz,
                    StringComparison.OrdinalIgnoreCase) ||
                dispositivo.Name.Contains(
                    interfazRed.Id,
                    StringComparison.OrdinalIgnoreCase))
            {
                dispositivoSeleccionado = dispositivo;
                break;
            }
        }

        if (dispositivoSeleccionado == null)
        {
            throw new InvalidOperationException(
                $"No se encontró el dispositivo de captura asociado a '{nombreInterfaz}'.");
        }

        IPInterfaceProperties propiedadesIp =
            interfazRed.GetIPProperties();

        IPAddress direccionIpLocal =
            propiedadesIp.UnicastAddresses
                .Where(direccion =>
                    direccion.Address.AddressFamily ==
                    AddressFamily.InterNetwork)
                .Select(direccion => direccion.Address)
                .FirstOrDefault();

        IPAddress puertaEnlace =
            propiedadesIp.GatewayAddresses
                .Select(gateway => gateway.Address)
                .FirstOrDefault(direccion =>
                    direccion.AddressFamily ==
                    AddressFamily.InterNetwork);

        if (direccionIpLocal == null)
        {
            throw new InvalidOperationException(
                $"La interfaz '{nombreInterfaz}' no tiene una dirección IPv4.");
        }

        if (puertaEnlace == null)
        {
            throw new InvalidOperationException(
                $"La interfaz '{nombreInterfaz}' no tiene una puerta de enlace IPv4 configurada.");
        }

        PhysicalAddress direccionMacLocal =
            interfazRed.GetPhysicalAddress();

        PhysicalAddress direccionMacBroadcast =
            new PhysicalAddress(
                new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

        PhysicalAddress direccionMacVacia =
            new PhysicalAddress(
                new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

        DispositivoDetectado resultado =
            new DispositivoDetectado();

        void CuandoLlegaPaquete(
            object sender,
            PacketCapture captura)
        {
            var capturaBruta = captura.GetPacket();

            if (capturaBruta.LinkLayerType != LinkLayers.Ethernet)
            {
                return;
            }

            Packet paquete =
                Packet.ParsePacket(
                    capturaBruta.LinkLayerType,
                    capturaBruta.Data);

            EthernetPacket ethernet =
                paquete as EthernetPacket;

            if (ethernet == null)
            {
                return;
            }

            ArpPacket arp =
                ethernet.PayloadPacket as ArpPacket;

            if (arp == null)
            {
                return;
            }

            // Aceptamos únicamente una respuesta ARP para la IP de la
            // puerta de enlace que acabamos de consultar.
            if (arp.Operation != ArpOperation.Response ||
                !arp.SenderProtocolAddress.Equals(puertaEnlace))
            {
                return;
            }

            // La MAC Ethernet y la MAC declarada por ARP deben coincidir.
            if (!ethernet.SourceHardwareAddress.Equals(
                    arp.SenderHardwareAddress))
            {
                return;
            }

            resultado.DireccionIP =
                arp.SenderProtocolAddress.ToString();

            resultado.DireccionMac =
                FormatearMac(arp.SenderHardwareAddress);

            // Solo buscamos el nombre si el dispositivo también anuncia
            // LLDP. Se resolverá más adelante sobre la misma MAC.
            LldpPacket lldp =
                ethernet.PayloadPacket as LldpPacket;

            if (lldp == null)
            {
                return;
            }

            foreach (Tlv tlv in lldp.TlvCollection)
            {
                if (tlv.Type != TlvType.SystemName)
                {
                    continue;
                }

                SystemNameTlv systemName =
                    (SystemNameTlv)tlv;

                resultado.Nombre =
                    systemName.Name;

                break;
            }
        }

        dispositivoSeleccionado.OnPacketArrival +=
            CuandoLlegaPaquete;

        dispositivoSeleccionado.Open();

        Console.WriteLine(
            $"Captura iniciada en: {dispositivoSeleccionado.Name}");

        try
        {
            // Primero comenzamos a escuchar y después enviamos una
            // consulta ARP específica a la puerta de enlace.
            dispositivoSeleccionado.StartCapture();

            ArpPacket solicitudArp =
                new ArpPacket(
                    ArpOperation.Request,
                    direccionMacVacia,
                    puertaEnlace,
                    direccionMacLocal,
                    direccionIpLocal);

            EthernetPacket tramaArp =
                new EthernetPacket(
                    direccionMacLocal,
                    direccionMacBroadcast,
                    EthernetType.Arp);

            tramaArp.PayloadPacket =
                solicitudArp;

            dispositivoSeleccionado.SendPacket(
                tramaArp.Bytes);

            Console.WriteLine(
                $"Consulta ARP enviada para: {puertaEnlace}");

            // Esperamos solamente la respuesta correspondiente.
            await EsperarResultadoAsync(
                resultado,
                TimeSpan.FromSeconds(3));
        }
        finally
        {
            dispositivoSeleccionado.StopCapture();

            dispositivoSeleccionado.OnPacketArrival -=
                CuandoLlegaPaquete;

            dispositivoSeleccionado.Close();

            Console.WriteLine("Captura finalizada.");
        }

        if (string.IsNullOrWhiteSpace(resultado.DireccionMac))
        {
            Console.WriteLine(
                $"No se recibió respuesta ARP para {puertaEnlace}.");
        }
        else
        {
            Console.WriteLine(
                $"Dispositivo identificado | " +
                $"IP: {resultado.DireccionIP} | " +
                $"MAC: {resultado.DireccionMac} | " +
                $"Nombre: {resultado.Nombre}");
        }

        return resultado;
    }

    private async Task EsperarResultadoAsync(
        DispositivoDetectado resultado,
        TimeSpan tiempoMaximo)
    {
        DateTime limite =
            DateTime.UtcNow.Add(tiempoMaximo);

        while (string.IsNullOrWhiteSpace(resultado.DireccionMac) &&
               DateTime.UtcNow < limite)
        {
            await Task.Delay(50);
        }
    }

    private string FormatearMac(PhysicalAddress direccionMac)
    {
        return BitConverter
            .ToString(direccionMac.GetAddressBytes())
            .Replace("-", ":");
    }
}
