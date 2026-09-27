using PacketDotNet;
using PacketDotNet.Lldp;
using ProyectoRed.Web.Models;
using SharpPcap;
using System.Net;
using System.Net.NetworkInformation;

namespace ProyectoRed.Web.Services;

public class CapturadorPaquetesService
{
    public async Task<DispositivoDetectado> CapturarAsync(
        string nombreInterfaz)
    {
        CaptureDeviceList dispositivos =
            CaptureDeviceList.Instance;

        // Buscamos primero la interfaz de red de .NET que corresponde
        // al nombre seleccionado en la aplicación.
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

        DispositivoDetectado resultado =
            new DispositivoDetectado();

        PhysicalAddress direccionMacLocal =
            interfazRed.GetPhysicalAddress();

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

            PhysicalAddress direccionMacOrigen =
                ethernet.SourceHardwareAddress;

            // Ignoramos los paquetes generados por nuestra propia PC.
            if (direccionMacOrigen.Equals(direccionMacLocal))
            {
                return;
            }

            // En una conexión directa, el primer MAC remoto que vemos
            // corresponde al dispositivo conectado al otro extremo.
            if (string.IsNullOrWhiteSpace(resultado.DireccionMac))
            {
                resultado.DireccionMac =
                    FormatearMac(direccionMacOrigen);
            }

            // ARP proporciona directamente MAC + IPv4 del emisor.
            ArpPacket arp =
                ethernet.PayloadPacket as ArpPacket;

            if (arp != null &&
                string.IsNullOrWhiteSpace(resultado.DireccionIP) &&
                arp.SenderProtocolAddress != null &&
                !IPAddress.IsAny(
                    arp.SenderProtocolAddress))
            {
                resultado.DireccionIP =
                    arp.SenderProtocolAddress.ToString();
            }

            // IPv4 permite obtener la dirección IP del origen.
            IPv4Packet ipv4 =
                ethernet.PayloadPacket as IPv4Packet;

            if (ipv4 != null &&
                string.IsNullOrWhiteSpace(resultado.DireccionIP) &&
                ipv4.SourceAddress != null &&
                !IPAddress.IsAny(ipv4.SourceAddress))
            {
                resultado.DireccionIP =
                    ipv4.SourceAddress.ToString();
            }

            // LLDP puede proporcionar el nombre del equipo.
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
            dispositivoSeleccionado.StartCapture();

            // Escuchamos durante unos segundos para permitir que el
            // dispositivo remoto genere tráfico.
            await Task.Delay(TimeSpan.FromSeconds(5));
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
                "No se detectó tráfico de un dispositivo remoto durante la prueba.");
        }
        else
        {
            Console.WriteLine(
                $"Dispositivo | " +
                $"IP: {resultado.DireccionIP} | " +
                $"MAC: {resultado.DireccionMac} | " +
                $"Nombre: {resultado.Nombre}");
        }

        return resultado;
    }

    private string FormatearMac(PhysicalAddress direccionMac)
    {
        return BitConverter
            .ToString(direccionMac.GetAddressBytes())
            .Replace("-", ":");
    }
}
