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

        PhysicalAddress direccionMacLocal =
            interfazRed.GetPhysicalAddress();

        // Cada dispositivo observado queda asociado a su MAC.
        // IP y nombre solamente se agregan al mismo candidato que
        // originó el paquete correspondiente.
        Dictionary<string, DispositivoDetectado> dispositivosObservados =
            new Dictionary<string, DispositivoDetectado>(
                StringComparer.OrdinalIgnoreCase);

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

            string macRemota =
                FormatearMac(direccionMacOrigen);

            if (!dispositivosObservados.TryGetValue(
                    macRemota,
                    out DispositivoDetectado resultado))
            {
                resultado = new DispositivoDetectado
                {
                    DireccionMac = macRemota
                };

                dispositivosObservados.Add(
                    macRemota,
                    resultado);
            }

            // ARP relaciona en la misma trama la MAC e IP del emisor.
            ArpPacket arp =
                ethernet.PayloadPacket as ArpPacket;

            if (arp != null &&
                arp.SenderProtocolAddress != null &&
                !arp.SenderProtocolAddress.Equals(IPAddress.Any))
            {
                resultado.DireccionIP =
                    arp.SenderProtocolAddress.ToString();
            }

            // IPv4 relaciona en la misma trama la MAC Ethernet e IP origen.
            IPv4Packet ipv4 =
                ethernet.PayloadPacket as IPv4Packet;

            if (ipv4 != null &&
                ipv4.SourceAddress != null &&
                !ipv4.SourceAddress.Equals(IPAddress.Any))
            {
                resultado.DireccionIP =
                    ipv4.SourceAddress.ToString();
            }

            // LLDP relaciona en la misma trama la MAC origen con
            // el System Name del dispositivo que anuncia.
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

            // La captura dura solamente unos segundos.
            // No dejamos el capturador ejecutándose indefinidamente.
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

        // Elegimos solamente candidatos cuya MAC e IP quedaron
        // relacionadas por tráfico originado por ese mismo MAC.
        DispositivoDetectado resultadoFinal =
            dispositivosObservados.Values
                .FirstOrDefault(dispositivo =>
                    !string.IsNullOrWhiteSpace(
                        dispositivo.DireccionIP));

        if (resultadoFinal == null)
        {
            resultadoFinal =
                dispositivosObservados.Values.FirstOrDefault()
                ?? new DispositivoDetectado();

            Console.WriteLine(
                "No se obtuvo una pareja MAC + IP durante la captura.");
        }
        else
        {
            Console.WriteLine(
                $"Dispositivo observado | " +
                $"IP: {resultadoFinal.DireccionIP} | " +
                $"MAC: {resultadoFinal.DireccionMac} | " +
                $"Nombre: {resultadoFinal.Nombre}");
        }

        return resultadoFinal;
    }

    private string FormatearMac(PhysicalAddress direccionMac)
    {
        return BitConverter
            .ToString(direccionMac.GetAddressBytes())
            .Replace("-", ":");
    }
}
