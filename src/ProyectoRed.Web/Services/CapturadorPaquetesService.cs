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
        var paquete = captura.GetPacket();

        Console.WriteLine(
            $"Paquete recibido - " +
            $"Longitud: {paquete.Data.Length} bytes");
    }
}