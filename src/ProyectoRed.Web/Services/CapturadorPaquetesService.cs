using PacketDotNet;
using SharpPcap;

namespace ProyectoRed.Web.Services;

public class CapturadorPaquetesService
{
    private bool paqueteMostrado;

    public async Task CapturarAsync(string nombreInterfaz)
    {
        paqueteMostrado = false;

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

            // La prueba dura solamente unos segundos.
            // Así evitamos dejar la captura funcionando indefinidamente.
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
    }

    private void CuandoLlegaPaquete(
        object sender,
        PacketCapture captura)
    {
        // No mostramos todas las tramas recibidas.
        // Solo necesitamos una para comprobar el análisis Ethernet.
        if (paqueteMostrado)
        {
            return;
        }

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

        paqueteMostrado = true;
    }
}
