using PacketDotNet;
using PacketDotNet.LLDP;
using SharpPcap;

namespace ProyectoRed.Web.Services;

public class CapturadorPaquetesService
{
    private bool lldpMostrado;

    public async Task CapturarAsync(string nombreInterfaz)
    {
        lldpMostrado = false;

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
            // No dejamos el capturador ejecutándose indefinidamente.
            await Task.Delay(TimeSpan.FromSeconds(5));
        }
        finally
        {
            dispositivoSeleccionado.StopCapture();

            dispositivoSeleccionado.OnPacketArrival -=
                CuandoLlegaPaquete;

            dispositivoSeleccionado.Close();

            if (!lldpMostrado)
            {
                Console.WriteLine(
                    "No se encontró ningún paquete LLDP durante la prueba.");
            }

            Console.WriteLine("Captura finalizada.");
        }
    }

    private void CuandoLlegaPaquete(
        object sender,
        PacketCapture captura)
    {
        // Solo necesitamos un paquete LLDP para esta prueba.
        // Ignoramos los siguientes para no generar una salida interminable.
        if (lldpMostrado)
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

        // LLDP utiliza el EtherType 0x88CC.
        if (ethernet.Type != EthernetType.LLDP)
        {
            return;
        }

        LLDPPacket lldp =
            ethernet.PayloadPacket as LLDPPacket;

        if (lldp == null)
        {
            return;
        }

        string nombreEquipo = string.Empty;

        foreach (var tlv in lldp)
        {
            if (tlv.Type == TLVTypes.SystemName)
            {
                SystemName systemName =
                    (SystemName)tlv;

                nombreEquipo =
                    systemName.StringValue;

                break;
            }
        }

        Console.WriteLine(
            $"LLDP | " +
            $"MAC: {ethernet.SourceHardwareAddress} | " +
            $"Nombre: {nombreEquipo}");

        lldpMostrado = true;
    }
}
