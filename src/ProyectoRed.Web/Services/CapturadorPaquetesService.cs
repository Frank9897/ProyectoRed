using PacketDotNet;
using SharpPcap;

namespace ProyectoRed.Web.Services;

public class CapturadorPaquetesService
{
    public void Capturar(string nombreInterfaz)
    {
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

        dispositivoSeleccionado.StartCapture();
    }

    private void CuandoLlegaPaquete(
        object sender,
        PacketCapture captura)
    {
        var capturaBruta = captura.GetPacket();

        // En esta etapa solo procesamos tramas Ethernet.
        if (capturaBruta.LinkLayerType != LinkLayers.Ethernet)
        {
            return;
        }

        // PacketDotNet interpreta los bytes capturados
        // según la capa de enlace de la captura.
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

        Console.WriteLine(
            $"Ethernet | " +
            $"Origen: {ethernet.SourceHardwareAddress} | " +
            $"Destino: {ethernet.DestinationHardwareAddress} | " +
            $"Tipo: {ethernet.Type} " +
            $"(0x{((ushort)ethernet.Type):X4}) | " +
            $"Longitud: {capturaBruta.Data.Length} bytes");
    }
}
