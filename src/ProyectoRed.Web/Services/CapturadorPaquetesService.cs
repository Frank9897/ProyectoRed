using PacketDotNet;
using PacketDotNet.Lldp;
using SharpPcap;
using System.Net.NetworkInformation;

namespace ProyectoRed.Web.Services;

public class CapturadorPaquetesService
{
    private bool lldpMostrado;

    public async Task CapturarAsync(string nombreInterfaz)
    {
        lldpMostrado = false;

        CaptureDeviceList dispositivos =
            CaptureDeviceList.Instance;

        // Buscamos primero la interfaz de red de .NET que corresponde
        // al nombre que seleccionó el usuario en la aplicación.
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
            // En Windows, SharpPcap identifica el adaptador mediante:
            // \Device\NPF_{GUID}
            // El GUID coincide con NetworkInterface.Id de .NET.
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
        if (ethernet.Type != EthernetType.Lldp)
        {
            return;
        }

        LldpPacket lldp =
            ethernet.PayloadPacket as LldpPacket;

        if (lldp == null)
        {
            return;
        }

        string nombreEquipo = string.Empty;

        foreach (Tlv tlv in lldp.TlvCollection)
        {
            if (tlv.Type == TlvType.SystemName)
            {
                SystemNameTlv systemName =
                    (SystemNameTlv)tlv;

                nombreEquipo =
                    systemName.Name;

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
