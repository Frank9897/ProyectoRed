using PacketDotNet;
using SharpPcap;

namespace ProyectoRed.Web.Services;

public class CapturadorPaquetesService
{
    private bool arpMostrado;

    public async Task CapturarAsync(string nombreInterfaz)
    {
        arpMostrado = false;

        CaptureDeviceList dispositivos =
            CaptureDeviceList.Instance;

        ICaptureDevice dispositivoSeleccionado = null;

        foreach (var dispositivo in dispositivos)
        {
            if (dispositivo.Name == nombreInterfaz)
            {
                dispositivoSeleccionado = dispositivo;
                break;
            }
        }

        if (dispositivoSeleccionado == null)
        {
            throw new InvalidOperationException(
                $"No se encontró el dispositivo de captura '{nombreInterfaz}'.");
        }

        dispositivoSeleccionado.OnPacketArrival +=
            CuandoLlegaPaquete;

        dispositivoSeleccionado.Open();

        Console.WriteLine(
            $"Captura iniciada en: {dispositivoSeleccionado.Name}");

        try
        {
            dispositivoSeleccionado.StartCapture();

            // La captura de esta prueba dura como máximo unos segundos.
            // No dejamos el capturador ejecutándose indefinidamente.
            await Task.Delay(TimeSpan.FromSeconds(5));
        }
        finally
        {
            dispositivoSeleccionado.StopCapture();

            dispositivoSeleccionado.OnPacketArrival -=
                CuandoLlegaPaquete;

            dispositivoSeleccionado.Close();

            if (!arpMostrado)
            {
                Console.WriteLine(
                    "No se encontró ningún paquete ARP durante la prueba.");
            }

            Console.WriteLine("Captura finalizada.");
        }
    }

    private void CuandoLlegaPaquete(
        object sender,
        PacketCapture captura)
    {
        // Ya encontramos un ARP para esta prueba.
        // Ignoramos los demás paquetes para no generar un bucle de salida.
        if (arpMostrado)
        {
            return;
        }

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

        // Solo nos interesan las tramas ARP.
        if (ethernet.Type != EthernetType.Arp)
        {
            return;
        }

        ArpPacket arp =
            ethernet.PayloadPacket as ArpPacket;

        if (arp == null)
        {
            return;
        }

        Console.WriteLine(
            $"ARP | " +
            $"Operación: {arp.Operation} | " +
            $"IP origen: {arp.SenderProtocolAddress} | " +
            $"MAC origen: {arp.SenderHardwareAddress} | " +
            $"IP destino: {arp.TargetProtocolAddress} | " +
            $"MAC destino: {arp.TargetHardwareAddress}");

        arpMostrado = true;
    }
}
