using PacketDotNet;
using PacketDotNet.Lldp;
using ProyectoRed.Web.Models;
using SharpPcap;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ProyectoRed.Web.Services;

public class CapturadorPaquetesService
{
    private readonly HistorialDispositivosService _historialDispositivosService;

    public CapturadorPaquetesService(
        HistorialDispositivosService historialDispositivosService)
    {
        _historialDispositivosService = historialDispositivosService;
    }

    public async Task<DispositivoDetectado> CapturarAsync(
        string nombreInterfaz,
        string direccionIPObjetivo = null,
        string direccionIPLocalManual = null)
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

        if (!string.IsNullOrWhiteSpace(direccionIPObjetivo) &&
            (!IPAddress.TryParse(
                direccionIPObjetivo,
                out IPAddress direccionObjetivo) ||
             direccionObjetivo.AddressFamily != AddressFamily.InterNetwork ||
             direccionObjetivo.Equals(IPAddress.Any) ||
             direccionObjetivo.Equals(IPAddress.Broadcast) ||
             direccionObjetivo.Equals(IPAddress.Loopback)))
        {
            throw new InvalidOperationException(
                "La IP del dispositivo indicada manualmente no es una IPv4 de destino válida.");
        }

        IPAddress direccionIpLocalManualParseada = null;

        if (!string.IsNullOrWhiteSpace(direccionIPLocalManual))
        {
            if (!IPAddress.TryParse(
                    direccionIPLocalManual,
                    out direccionIpLocalManualParseada) ||
                direccionIpLocalManualParseada.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new InvalidOperationException(
                    "La IP local manual indicada no es una IPv4 válida.");
            }
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


        // La IPv4 y la puerta de enlace son necesarias únicamente para
        // realizar la consulta ARP dirigida al gateway. La captura
        // pasiva puede funcionar sin ninguna de las dos.
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

        bool vecinoDirectoDetectado = false;

        Dictionary<string, string> nombresLldpPorMac =
            new Dictionary<string, string>(
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

            // LLDP identifica al vecino directamente conectado al puerto.
            // Lo analizamos sobre los bytes crudos para no depender de
            // que PacketDotNet reconozca el encapsulado o una VLAN.
            if (IntentarExtraerInformacionLldp(
                    capturaBruta.Data,
                    out string macLldpDirecta,
                    out string nombreLldpDirecto,
                    out string direccionGestionLldp))
            {
                vecinoDirectoDetectado = true;
                resultado.DireccionMac = macLldpDirecta;
                resultado.DireccionIP =
                    direccionGestionLldp ?? string.Empty;
                resultado.Nombre =
                    nombreLldpDirecto ?? string.Empty;

                return;
            }

            // CDP también identifica al vecino directamente conectado.
            string nombreCdp =
                IntentarExtraerNombreCdp(
                    capturaBruta.Data,
                    out string macCdp);

            if (nombreCdp != null)
            {
                vecinoDirectoDetectado = true;
                resultado.DireccionMac = macCdp;
                resultado.DireccionIP = string.Empty;
                resultado.Nombre = nombreCdp;

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

            // LLDP puede aparecer antes o después de la respuesta ARP.
            // Guardamos el nombre asociado a su MAC para poder unirlo
            // posteriormente con el mismo dispositivo.
            LldpPacket lldp =
                ethernet.PayloadPacket as LldpPacket;

            if (lldp != null && !vecinoDirectoDetectado)
            {
                string macLldp =
                    FormatearMac(ethernet.SourceHardwareAddress);

                foreach (Tlv tlv in lldp.TlvCollection)
                {
                    if (tlv.Type != TlvType.SystemName)
                    {
                        continue;
                    }

                    SystemNameTlv systemName =
                        (SystemNameTlv)tlv;

                    nombresLldpPorMac[macLldp] =
                        systemName.Name;

                    if (string.Equals(
                            macLldp,
                            resultado.DireccionMac,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        resultado.Nombre =
                            systemName.Name;
                    }

                    break;
                }

                // Algunos dispositivos anuncian su IP de gestión
                // mediante el Management Address TLV de LLDP.
                // Esto permite identificar un switch aunque no exista
                // una puerta de enlace configurada en la PC.
                if (string.IsNullOrWhiteSpace(resultado.DireccionMac))
                {
                    string direccionGestionLldpAnterior =
                        IntentarExtraerDireccionGestionLldp(
                            capturaBruta.Data);

                    if (!string.IsNullOrWhiteSpace(
                            direccionGestionLldpAnterior))
                    {
                        resultado.DireccionIP =
                            direccionGestionLldpAnterior;

                        resultado.DireccionMac =
                            macLldp;
                    }
                }

                return;
            }

            ArpPacket arp =
                ethernet.PayloadPacket as ArpPacket;

            if (arp == null)
            {
                return;
            }

            // Aceptamos cualquier respuesta ARP que llegue por este
            // cable: puede ser del gateway (si respondió a nuestra
            // consulta dirigida) o de cualquier otro dispositivo
            // conectado directamente (switch, PC, etc.) que haya
            // emitido ARP de forma espontánea (gratuitous ARP,
            // resolución hacia otro host, etc.). Esto es lo que
            // permite detectar el switch de piso aunque no sea
            // la puerta de enlace de la red.
            if (arp.Operation != ArpOperation.Response)
            {
                return;
            }

            // Si LLDP/CDP ya identificó al vecino directamente
            // conectado, no lo reemplazamos con tráfico ARP.
            if (vecinoDirectoDetectado)
            {
                return;
            }

            IPAddress direccionArpEsperada = null;

            if (!string.IsNullOrWhiteSpace(direccionIPObjetivo) &&
                IPAddress.TryParse(
                    direccionIPObjetivo,
                    out IPAddress direccionObjetivoArp))
            {
                direccionArpEsperada = direccionObjetivoArp;
            }
            else if (direccionIpLocal != null &&
                     puertaEnlace != null)
            {
                direccionArpEsperada = puertaEnlace;
            }

            // Cuando existe una consulta ARP dirigida, solo aceptamos
            // la respuesta de esa IP. Esto evita tomar otra respuesta
            // como si fuera el dispositivo conectado.

            // Cuando existe una consulta dirigida, la respuesta
            // debe corresponder exactamente a esa IP.
            if (direccionArpEsperada != null &&
                !arp.SenderProtocolAddress.Equals(
                    direccionArpEsperada))
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

            string macResultado =
                resultado.DireccionMac;

            if (nombresLldpPorMac.TryGetValue(
                    macResultado,
                    out string nombreLldp))
            {
                resultado.Nombre =
                    nombreLldp;
            }
        }

        dispositivoSeleccionado.OnPacketArrival +=
            CuandoLlegaPaquete;

        dispositivoSeleccionado.Open();

        Console.WriteLine(
            $"Captura iniciada en: {dispositivoSeleccionado.Name}");

        try
        {
            // Comenzamos a escuchar antes de cualquier consulta.
            dispositivoSeleccionado.StartCapture();

            IPAddress direccionDestinoArp = null;
            IPAddress direccionOrigenArp =
                direccionIpLocal ??
                direccionIpLocalManualParseada ??
                IPAddress.Any;

            bool consultaArpDirigida = false;

            if (!string.IsNullOrWhiteSpace(direccionIPObjetivo))
            {
                direccionDestinoArp =
                    IPAddress.Parse(direccionIPObjetivo);

                consultaArpDirigida = true;
            }
            else if (direccionIpLocal != null &&
                     puertaEnlace != null)
            {
                direccionDestinoArp = puertaEnlace;
                consultaArpDirigida = true;
            }

            if (consultaArpDirigida)
            {
                ArpPacket solicitudArp =
                    new ArpPacket(
                        ArpOperation.Request,
                        direccionMacVacia,
                        direccionDestinoArp,
                        direccionMacLocal,
                        direccionOrigenArp);

                EthernetPacket tramaArp =
                    new EthernetPacket(
                        direccionMacLocal,
                        direccionMacBroadcast,
                        EthernetType.Arp);

                tramaArp.PayloadPacket =
                    solicitudArp;

                if (dispositivoSeleccionado is not IInjectionDevice dispositivoInyeccion)
                {
                    throw new InvalidOperationException(
                        "El dispositivo de captura seleccionado no permite inyección de paquetes.");
                }

                dispositivoInyeccion.SendPacket(tramaArp);

                if (!string.IsNullOrWhiteSpace(direccionIPObjetivo))
                {
                    Console.WriteLine(
                        $"Consulta ARP manual enviada para: {direccionDestinoArp}");
                }
                else
                {
                    Console.WriteLine(
                        $"Consulta ARP enviada para: {direccionDestinoArp}");
                }
            }
            else
            {
                Console.WriteLine(
                    "No hay destino ARP conocido. " +
                    "Se realizará descubrimiento pasivo mediante el tráfico recibido.");
            }

            TimeSpan tiempoEspera =
                consultaArpDirigida
                    ? TimeSpan.FromSeconds(3)
                    : TimeSpan.FromSeconds(5);

            await EsperarResultadoAsync(
                resultado,
                tiempoEspera);
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
            if (puertaEnlace != null)
            {
                Console.WriteLine(
                    $"No se recibió una respuesta ARP para {puertaEnlace}.");
            }
            else
            {
                Console.WriteLine(
                    "No se detectó ningún dispositivo durante la captura pasiva.");
            }
        }
        else
        {
            Console.WriteLine(
                $"Dispositivo identificado | " +
                $"IP: {resultado.DireccionIP} | " +
                $"MAC: {resultado.DireccionMac} | " +
                $"Nombre: {resultado.Nombre}");

            await _historialDispositivosService.RegistrarAsync(
                new RegistroDispositivo
                {
                    DireccionIP = resultado.DireccionIP,
                    DireccionMac = resultado.DireccionMac,
                    Nombre = resultado.Nombre,
                    NombreInterfaz = nombreInterfaz,
                    Origen = "ARP",
                    FechaDeteccion = DateTime.Now
                });
        }

        return resultado;
    }

    private bool IntentarExtraerInformacionLldp(
        byte[] datos,
        out string macOrigen,
        out string nombreSistema,
        out string direccionGestion)
    {
        macOrigen = null;
        nombreSistema = null;
        direccionGestion = null;

        if (datos == null ||
            datos.Length < 18)
        {
            return false;
        }

        int desplazamientoEthernet = 14;

        ushort tipoEthernet =
            (ushort)((datos[12] << 8) | datos[13]);

        if (tipoEthernet == 0x8100 ||
            tipoEthernet == 0x88A8)
        {
            if (datos.Length < 22)
            {
                return false;
            }

            tipoEthernet =
                (ushort)((datos[16] << 8) | datos[17]);

            desplazamientoEthernet = 18;
        }

        if (tipoEthernet != 0x88CC)
        {
            return false;
        }

        macOrigen =
            FormatearMac(
                new PhysicalAddress(
                    datos.Skip(6).Take(6).ToArray()));

        int posicion =
            desplazamientoEthernet;

        while (posicion + 2 <= datos.Length)
        {
            ushort encabezado =
                (ushort)((datos[posicion] << 8) |
                         datos[posicion + 1]);

            int tipo =
                encabezado >> 9;

            int longitud =
                encabezado & 0x01FF;

            posicion += 2;

            if (tipo == 0)
            {
                break;
            }

            if (posicion + longitud > datos.Length)
            {
                return true;
            }

            // Tipo 5 = System Name.
            if (tipo == 5 &&
                longitud > 0)
            {
                nombreSistema =
                    System.Text.Encoding.UTF8.GetString(
                        datos,
                        posicion,
                        longitud);
            }

            // Tipo 8 = Management Address.
            if (tipo == 8 &&
                longitud >= 8)
            {
                int longitudDireccion =
                    datos[posicion];

                if (longitudDireccion == 5 &&
                    datos[posicion + 1] == 1)
                {
                    direccionGestion =
                        new IPAddress(
                            new byte[]
                            {
                                datos[posicion + 2],
                                datos[posicion + 3],
                                datos[posicion + 4],
                                datos[posicion + 5]
                            }).ToString();
                }
            }

            posicion += longitud;
        }

        return true;
    }

    private string IntentarExtraerDireccionGestionLldp(
        byte[] datos)
    {
        if (datos == null ||
            datos.Length < 18)
        {
            return null;
        }

        int desplazamientoEthernet = 14;

        ushort tipoEthernet =
            (ushort)((datos[12] << 8) | datos[13]);

        // VLAN 802.1Q: el EtherType se encuentra cuatro bytes
        // después del encabezado Ethernet original.
        if (tipoEthernet == 0x8100 ||
            tipoEthernet == 0x88A8)
        {
            if (datos.Length < 22)
            {
                return null;
            }

            tipoEthernet =
                (ushort)((datos[16] << 8) | datos[17]);

            desplazamientoEthernet = 18;
        }

        if (tipoEthernet != 0x88CC)
        {
            return null;
        }

        int posicion =
            desplazamientoEthernet;

        while (posicion + 2 <= datos.Length)
        {
            ushort encabezado =
                (ushort)((datos[posicion] << 8) |
                         datos[posicion + 1]);

            int tipo =
                encabezado >> 9;

            int longitud =
                encabezado & 0x01FF;

            posicion += 2;

            if (tipo == 0)
            {
                return null;
            }

            if (posicion + longitud > datos.Length)
            {
                return null;
            }

            if (tipo == 8)
            {
                if (longitud < 1)
                {
                    return null;
                }

                int longitudDireccion =
                    datos[posicion];

                if (longitudDireccion != 5 ||
                    longitud < longitudDireccion + 7)
                {
                    return null;
                }

                // Subtipo 1 = IPv4.
                if (datos[posicion + 1] != 1)
                {
                    return null;
                }

                return new IPAddress(
                    new byte[]
                    {
                        datos[posicion + 2],
                        datos[posicion + 3],
                        datos[posicion + 4],
                        datos[posicion + 5]
                    }).ToString();
            }

            posicion += longitud;
        }

        return null;
    }

    /// <summary>
    /// Busca una trama CDP dentro de los bytes crudos del frame
    /// (LLC/SNAP con OUI Cisco 00-00-0C y PID 0x2000) y, si la
    /// encuentra, extrae el TLV Device-ID (tipo 0x0001). Devuelve
    /// null si el frame no es CDP.
    /// </summary>
    private string IntentarExtraerNombreCdp(
        byte[] datos,
        out string macOrigen)
    {
        macOrigen = null;

        // Mínimo: 6 (dst) + 6 (src) + 2 (len) + 3 (LLC) + 5 (SNAP) + 4 (CDP header)
        const int longitudMinima = 26;

        if (datos == null || datos.Length < longitudMinima)
        {
            return null;
        }

        // LLC: DSAP=0xAA SSAP=0xAA Control=0x03, arranca en el byte 14
        // (después de las dos MAC y el campo "longitud" de 802.3).
        if (datos[14] != 0xAA ||
            datos[15] != 0xAA ||
            datos[16] != 0x03)
        {
            return null;
        }

        // SNAP: OUI Cisco = 00-00-0C, PID CDP = 0x2000.
        if (datos[17] != 0x00 ||
            datos[18] != 0x00 ||
            datos[19] != 0x0C ||
            datos[20] != 0x20 ||
            datos[21] != 0x00)
        {
            return null;
        }

        // Cabecera CDP: version(1) ttl(1) checksum(2). Los TLV
        // arrancan en el byte 26.
        int posicion = 26;

        while (posicion + 4 <= datos.Length)
        {
            int tipoTlv =
                (datos[posicion] << 8) | datos[posicion + 1];

            int longitudTlv =
                (datos[posicion + 2] << 8) | datos[posicion + 3];

            if (longitudTlv < 4 ||
                posicion + longitudTlv > datos.Length)
            {
                break;
            }

            // Tipo 0x0001 = Device-ID.
            if (tipoTlv == 0x0001)
            {
                int longitudValor =
                    longitudTlv - 4;

                string deviceId =
                    System.Text.Encoding.ASCII.GetString(
                        datos,
                        posicion + 4,
                        longitudValor);

                macOrigen =
                    FormatearMac(
                        new PhysicalAddress(
                            datos.Skip(6).Take(6).ToArray()));

                return deviceId;
            }

            posicion += longitudTlv;
        }

        return null;
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
