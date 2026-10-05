using PacketDotNet;
using ProyectoRed.Web.Models;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ProyectoRed.Web.Services;

public class CapturadorPaquetesService
{
    private readonly HistorialDispositivosService _historialDispositivosService;
    private readonly FabricanteMacService _fabricanteMacService;

    public string UltimoOrigenDeteccion { get; private set; } = string.Empty;

    public string UltimoFabricanteDeteccion { get; private set; } = string.Empty;

    public string UltimaConfianzaDeteccion { get; private set; } = string.Empty;

    public int UltimoPuntajeDeteccion { get; private set; }

    public string UltimaRazonDeteccion { get; private set; } = string.Empty;

    public long UltimaDuracionDeteccionMs { get; private set; }

    public long UltimaEstimacionDeteccionMs { get; private set; }

    public string UltimaFaseDeteccion { get; private set; } = string.Empty;

    public int UltimaCantidadSondasArp { get; private set; }

    public string UltimoCriterioBusqueda { get; private set; } = string.Empty;

    public bool UltimoUsoHistorial { get; private set; }

    // Estimación/fallback del envío individual fuera de Windows.
    private const int TamanoLoteArp = 256;

    private const int PausaLoteArpMs = 10;

    // 5.000 solicitudes ARP por segundo como máximo en la cola
    // nativa. Evitamos inundar el switch/Npcap y perder respuestas.
    private const int IntervaloSondaArpMicrosegundos = 200;

    private int _sondasArpActuales;

    public CapturadorPaquetesService(
        HistorialDispositivosService historialDispositivosService,
        FabricanteMacService fabricanteMacService)
    {
        _historialDispositivosService = historialDispositivosService;
        _fabricanteMacService = fabricanteMacService;
    }

    public async Task<DispositivoDetectado> CapturarAsync(
        string nombreInterfaz,
        string direccionIPObjetivo = null,
        string direccionMacObjetivo = null)
    {
        UltimoOrigenDeteccion = string.Empty;
        UltimoFabricanteDeteccion = string.Empty;
        UltimaConfianzaDeteccion = string.Empty;
        UltimoPuntajeDeteccion = 0;
        UltimaRazonDeteccion = string.Empty;
        UltimaDuracionDeteccionMs = 0;
        UltimaEstimacionDeteccionMs = 0;
        UltimaFaseDeteccion = "Preparando detección";
        UltimoCriterioBusqueda = "Automática";
        UltimoUsoHistorial = false;
        Interlocked.Exchange(
            ref _sondasArpActuales,
            0);

        UltimaCantidadSondasArp = 0;

        System.Diagnostics.Stopwatch cronometro =
            System.Diagnostics.Stopwatch.StartNew();

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

        Dictionary<string, string> cacheMacNormalizadas =
            new Dictionary<string, string>(
                StringComparer.OrdinalIgnoreCase);

        string NormalizarMacCacheada(string direccionMac)
        {
            if (string.IsNullOrWhiteSpace(direccionMac))
            {
                return string.Empty;
            }

            string clave =
                direccionMac.Trim();

            if (cacheMacNormalizadas.TryGetValue(
                    clave,
                    out string macNormalizada))
            {
                return macNormalizada;
            }

            macNormalizada =
                NormalizarMac(direccionMac);

            cacheMacNormalizadas[clave] =
                macNormalizada;

            return macNormalizada;
        }

        string macObjetivoNormalizada =
            NormalizarMacCacheada(direccionMacObjetivo);

        if (!string.IsNullOrWhiteSpace(direccionMacObjetivo) &&
            string.IsNullOrWhiteSpace(macObjetivoNormalizada))
        {
            throw new InvalidOperationException(
                "La MAC del dispositivo indicada no tiene un formato válido. " +
                "Use AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF o AABBCCDDEEFF.");
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


        IPAddress mascaraRedLocal =
            propiedadesIp.UnicastAddresses
                .Where(direccion =>
                    direccion.Address.AddressFamily ==
                    AddressFamily.InterNetwork)
                .Select(direccion => direccion.IPv4Mask)
                .FirstOrDefault();

        // La detección automática utiliza la IPv4 y la máscara local cuando
        // están disponibles. La puerta de enlace se usa solo como candidato
        // prioritario; no es un requisito para descubrir el dispositivo.
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
        string macVecinoDirecto = string.Empty;
        string origenDeteccion = string.Empty;

        HashSet<uint> objetivosArpActivos =
            new HashSet<uint>();

        Dictionary<uint, Dictionary<string, int>> respuestasArp =
            new Dictionary<uint, Dictionary<string, int>>();

        object sincronizacionArp =
            new object();

        List<RegistroDispositivo> historial =
            await _historialDispositivosService.ObtenerHistorialAsync();

        bool usoMacIndicada =
            !string.IsNullOrWhiteSpace(macObjetivoNormalizada);

        bool usoMacDelHistorial = false;

        if (!usoMacIndicada &&
            !string.IsNullOrWhiteSpace(direccionIPObjetivo))
        {
            RegistroDispositivo registroHistorico =
                historial
                    .Where(registro =>
                        string.Equals(
                            registro.NombreInterfaz,
                            nombreInterfaz,
                            StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(
                            registro.DireccionIP,
                            direccionIPObjetivo.Trim(),
                            StringComparison.OrdinalIgnoreCase) &&
                        !string.IsNullOrWhiteSpace(
                            registro.DireccionMac))
                    .OrderByDescending(
                        registro => registro.FechaDeteccion)
                    .FirstOrDefault();

            string macHistorial =
                NormalizarMacCacheada(
                    registroHistorico?.DireccionMac);

            if (!string.IsNullOrWhiteSpace(macHistorial))
            {
                macObjetivoNormalizada =
                    macHistorial;

                usoMacDelHistorial = true;
            }
        }

        bool busquedaPorIp =
            !string.IsNullOrWhiteSpace(direccionIPObjetivo) &&
            !usoMacDelHistorial;

        bool busquedaPorMac =
            !string.IsNullOrWhiteSpace(macObjetivoNormalizada);

        UltimoUsoHistorial =
            usoMacDelHistorial;

        UltimoCriterioBusqueda =
            usoMacDelHistorial
                ? "Historial → MAC"
                : usoMacIndicada
                    ? "MAC"
                    : busquedaPorIp
                        ? "IP"
                        : "Automática";

        HashSet<string> ipsHistoricas =
            historial
                .Where(registro =>
                    string.Equals(
                        registro.NombreInterfaz,
                        nombreInterfaz,
                        StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(
                        registro.DireccionIP))
                .Select(registro =>
                    registro.DireccionIP)
                .ToHashSet(
                    StringComparer.OrdinalIgnoreCase);

        HashSet<string> macsHistoricas =
            historial
                .Where(registro =>
                    string.Equals(
                        registro.NombreInterfaz,
                        nombreInterfaz,
                        StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(
                        registro.DireccionMac))
                .Select(registro =>
                    registro.DireccionMac)
                .ToHashSet(
                    StringComparer.OrdinalIgnoreCase);

        void RegistrarOrigen(string origen)
        {
            if (string.IsNullOrWhiteSpace(origen))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(origenDeteccion))
            {
                origenDeteccion = origen;
                return;
            }

            if (origenDeteccion.Contains(
                    origen,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            origenDeteccion += $" + {origen}";
        }

        void RegistrarFabricante(string fabricante)
        {
            if (string.IsNullOrWhiteSpace(fabricante) ||
                fabricante.Equals(
                    "Fabricante no identificado por OUI",
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(
                    UltimoFabricanteDeteccion) ||
                UltimoFabricanteDeteccion.Equals(
                    "Fabricante no identificado por OUI",
                    StringComparison.OrdinalIgnoreCase))
            {
                UltimoFabricanteDeteccion =
                    fabricante;
            }
        }

        bool MacCoincideObjetivo(string direccionMac)
        {
            return busquedaPorMac &&
                   string.Equals(
                       NormalizarMacCacheada(direccionMac),
                       macObjetivoNormalizada,
                       StringComparison.OrdinalIgnoreCase);
        }

        bool EsNuestraMac(PhysicalAddress direccionMac)
        {
            return direccionMacLocal != null &&
                   direccionMacLocal.GetAddressBytes().Length == 6 &&
                   direccionMac.Equals(direccionMacLocal);
        }

        void RegistrarCoincidenciaMac()
        {
            if (!busquedaPorMac)
            {
                return;
            }

            UltimaConfianzaDeteccion =
                usoMacDelHistorial
                    ? "Confirmado por MAC del historial"
                    : "Confirmado por MAC objetivo";

            UltimaRazonDeteccion =
                "La MAC observada coincide exactamente con la MAC buscada.";
        }

        void RegistrarRespuestaArp(
            IPAddress direccionIp,
            string direccionMac)
        {
            if (direccionIp == null ||
                string.IsNullOrWhiteSpace(direccionMac) ||
                EsDireccionEspecial(direccionIp))
            {
                return;
            }

            uint ip =
                ConvertirIPv4(direccionIp);

            lock (sincronizacionArp)
            {
                if (!respuestasArp.TryGetValue(
                        ip,
                        out Dictionary<string, int> macs))
                {
                    macs =
                        new Dictionary<string, int>(
                            StringComparer.OrdinalIgnoreCase);

                    respuestasArp[ip] =
                        macs;
                }

                macs.TryGetValue(
                    direccionMac,
                    out int cantidad);

                macs[direccionMac] =
                    cantidad + 1;
            }
        }

        bool EsNuestraIp(IPAddress direccionIp)
        {
            return direccionIpLocal != null &&
                   direccionIp.Equals(direccionIpLocal);
        }

        void CuandoLlegaPaquete(
            object sender,
            PacketCapture captura)
        {
            var capturaBruta =
                captura.GetPacket();

            if (capturaBruta.LinkLayerType !=
                LinkLayers.Ethernet)
            {
                return;
            }

            // LLDP identifica al vecino conectado al puerto.
            if (IntentarExtraerInformacionLldp(
                    capturaBruta.Data,
                    out string macLldpDirecta,
                    out string nombreLldpDirecto,
                    out string direccionGestionLldp) &&
                (!busquedaPorMac || MacCoincideObjetivo(macLldpDirecta)))
            {
                vecinoDirectoDetectado = true;
                macVecinoDirecto = macLldpDirecta;

                resultado.DireccionMac =
                    macLldpDirecta;

                resultado.Nombre =
                    nombreLldpDirecto ?? string.Empty;

                RegistrarOrigen("LLDP");
                RegistrarCoincidenciaMac();
                RegistrarFabricante(
                    _fabricanteMacService.ObtenerFabricante(
                        macLldpDirecta));

                // En detección manual la IP introducida por el técnico
                // sigue siendo la dirección objetivo. Si LLDP solo aporta
                // MAC/nombre, continuamos para completar la IP mediante ARP.
                if (!string.IsNullOrWhiteSpace(direccionGestionLldp) &&
                    !busquedaPorIp)
                {
                    resultado.DireccionIP =
                        direccionGestionLldp;

                    return;
                }
            }

            // HPSW es un protocolo legacy de switches HP que viaja
            // sobre HP Extended LLC. Cuando aparece en la interfaz física,
            // identifica directamente al equipo vecino y puede aportar
            // nombre e IP de administración.
            if (IntentarExtraerInformacionHpsw(
                    capturaBruta.Data,
                    out string macHpsw,
                    out string nombreHpsw,
                    out string direccionGestionHpsw) &&
                (!busquedaPorMac || MacCoincideObjetivo(macHpsw)))
            {
                vecinoDirectoDetectado = true;
                macVecinoDirecto = macHpsw;

                resultado.DireccionMac =
                    macHpsw;

                resultado.Nombre =
                    nombreHpsw ?? string.Empty;

                RegistrarOrigen("HPSW");
                RegistrarCoincidenciaMac();
                RegistrarFabricante(
                    _fabricanteMacService.ObtenerFabricante(
                        macHpsw));

                if (!string.IsNullOrWhiteSpace(direccionGestionHpsw) &&
                    !busquedaPorIp)
                {
                    resultado.DireccionIP =
                        direccionGestionHpsw;

                    return;
                }
            }

            // NDP/HGMPv2 es un mecanismo legacy de H3C/3Com para
            // anunciar información del vecino en capa 2. En esta primera
            // incorporación no intentamos interpretar campos internos
            // que no están suficientemente documentados; usamos la trama
            // como prueba fuerte de vecino local y conservamos la MAC de
            // origen. Después el ARP queda restringido a esa misma MAC,
            // lo que permite recuperar la IPv4 de administración sin
            // convertir el descubrimiento en un escaneo diferente.
            if (IntentarExtraerInformacionNdp(
                    capturaBruta.Data,
                    out string macNdp) &&
                (!busquedaPorMac || MacCoincideObjetivo(macNdp)))
            {
                vecinoDirectoDetectado = true;
                macVecinoDirecto = macNdp;

                resultado.DireccionMac =
                    macNdp;

                RegistrarOrigen("NDP/HGMPv2");
                RegistrarCoincidenciaMac();
                RegistrarFabricante(
                    _fabricanteMacService.ObtenerFabricante(
                        macNdp));
            }

            // EDP es un protocolo propietario de Extreme Networks
            // encapsulado mediante LLC/SNAP. Cuando está presente,
            // identifica directamente al switch vecino y puede transportar
            // una IP de interfaz VLAN.
            if (IntentarExtraerInformacionEdp(
                    capturaBruta.Data,
                    out string macEdp,
                    out string nombreEdp,
                    out string direccionGestionEdp) &&
                (!busquedaPorMac || MacCoincideObjetivo(macEdp)))
            {
                vecinoDirectoDetectado = true;
                macVecinoDirecto = macEdp;

                resultado.DireccionMac =
                    macEdp;

                resultado.Nombre =
                    nombreEdp ?? string.Empty;

                RegistrarOrigen("EDP");
                RegistrarCoincidenciaMac();
                RegistrarFabricante(
                    _fabricanteMacService.ObtenerFabricante(
                        macEdp));
                RegistrarFabricante("Extreme Networks");

                if (!string.IsNullOrWhiteSpace(direccionGestionEdp) &&
                    !busquedaPorIp)
                {
                    resultado.DireccionIP =
                        direccionGestionEdp;

                    return;
                }
            }

            if (IntentarExtraerInformacionFdp(
                    capturaBruta.Data,
                    out string macFdp,
                    out string nombreFdp,
                    out string direccionGestionFdp) &&
                (!busquedaPorMac || MacCoincideObjetivo(macFdp)))
            {
                vecinoDirectoDetectado = true;
                macVecinoDirecto = macFdp;

                resultado.DireccionMac =
                    macFdp;

                resultado.Nombre =
                    nombreFdp ?? string.Empty;

                RegistrarOrigen("FDP");
                RegistrarCoincidenciaMac();
                RegistrarFabricante(
                    _fabricanteMacService.ObtenerFabricante(
                        macFdp));

                if (!string.IsNullOrWhiteSpace(direccionGestionFdp) &&
                    !busquedaPorIp)
                {
                    resultado.DireccionIP =
                        direccionGestionFdp;

                    return;
                }
            }

            // STP/RSTP identifica al puente conectado al puerto.
            // Las BPDUs son tramas de enlace local y no se reenvían
            // como tráfico IP por otros switches.
            if (IntentarExtraerInformacionStp(
                    capturaBruta.Data,
                    out string macStp) &&
                (!busquedaPorMac || MacCoincideObjetivo(macStp)))
            {
                vecinoDirectoDetectado = true;
                macVecinoDirecto = macStp;

                resultado.DireccionMac =
                    macStp;

                RegistrarOrigen("STP");
                RegistrarCoincidenciaMac();
                RegistrarFabricante(
                    _fabricanteMacService.ObtenerFabricante(
                        macStp));

                return;
            }

            // CDP identifica de la misma forma al vecino Cisco y, cuando
            // el anuncio contiene direcciones, puede aportar la IP.
            IntentarExtraerInformacionCdp(
                capturaBruta.Data,
                out string macCdp,
                out string nombreCdp,
                out string direccionGestionCdp);

            if (!string.IsNullOrWhiteSpace(macCdp) &&
                (!busquedaPorMac ||
                 MacCoincideObjetivo(macCdp)))
            {
                vecinoDirectoDetectado = true;
                macVecinoDirecto = macCdp;

                resultado.DireccionMac =
                    macCdp;

                if (!string.IsNullOrWhiteSpace(nombreCdp))
                {
                    resultado.Nombre =
                        nombreCdp;
                }

                RegistrarOrigen("CDP");
                RegistrarCoincidenciaMac();
                RegistrarFabricante(
                    _fabricanteMacService.ObtenerFabricante(
                        macCdp));
                RegistrarFabricante("Cisco Systems");

                if (!string.IsNullOrWhiteSpace(direccionGestionCdp) &&
                    !busquedaPorIp)
                {
                    resultado.DireccionIP =
                        direccionGestionCdp;

                    return;
                }
            }

            Packet paquete =
                Packet.ParsePacket(
                    capturaBruta.LinkLayerType,
                    capturaBruta.Data);

            if (paquete is not EthernetPacket ethernet)
            {
                return;
            }

            // No inferimos la IP de gestión a partir de un paquete IPv4
            // genérico. Un router puede usar su MAC LAN como origen Ethernet
            // mientras transporta tráfico cuya IP de origen pertenece a Internet
            // (por ejemplo, una respuesta desde un servidor público). Esa IP no
            // es la IP del vecino conectado.
            
            ArpPacket arp =
                ethernet.PayloadPacket as ArpPacket;

            if (arp == null ||
                (arp.Operation != ArpOperation.Response &&
                 arp.Operation != ArpOperation.Request))
            {
                return;
            }

            if (EsNuestraIp(arp.SenderProtocolAddress) ||
                EsNuestraMac(arp.SenderHardwareAddress))
            {
                return;
            }

            string macFuenteArp =
                FormatearMac(
                    arp.SenderHardwareAddress);

            if (busquedaPorMac &&
                !MacCoincideObjetivo(macFuenteArp))
            {
                return;
            }

            if (busquedaPorMac &&
                !EsDireccionEspecial(
                    arp.SenderProtocolAddress))
            {
                RegistrarRespuestaArp(
                    arp.SenderProtocolAddress,
                    macFuenteArp);

                resultado.DireccionMac =
                    macFuenteArp;

                RegistrarOrigen(
                    usoMacDelHistorial
                        ? "ARP por MAC (historial)"
                        : "ARP por MAC");

                RegistrarCoincidenciaMac();

                return;
            }

            // Una solicitud ARP del vecino también puede revelar
            // directamente su IPv4 de origen. Es especialmente útil
            // cuando el equipo anuncia quién es mediante tráfico ARP
            // pero no tiene LLDP/CDP.
            if (arp.Operation == ArpOperation.Request &&
                !EsDireccionEspecial(
                    arp.SenderProtocolAddress))
            {
                if (vecinoDirectoDetectado &&
                    string.Equals(
                        macFuenteArp,
                        macVecinoDirecto,
                        StringComparison.OrdinalIgnoreCase))
                {
                    RegistrarRespuestaArp(
                        arp.SenderProtocolAddress,
                        macFuenteArp);

                    RegistrarOrigen("ARP");
                    RegistrarFabricante(
                        _fabricanteMacService.ObtenerFabricante(
                            macFuenteArp));

                    return;
                }

                RegistrarRespuestaArp(
                    arp.SenderProtocolAddress,
                    macFuenteArp);

                RegistrarOrigen("ARP");
                RegistrarFabricante(
                    _fabricanteMacService.ObtenerFabricante(
                        macFuenteArp));

                return;
            }

            // Si LLDP/CDP identificó un vecino directo, conservamos cualquier
            // ARP procedente de esa misma MAC aunque la IPv4 no pertenezca a
            // los rangos que ProyectoRed pudo generar para el sondeo activo.
            // La selección final puede comparar varias IPv4 asociadas al vecino.
            if (vecinoDirectoDetectado &&
                string.Equals(
                    macFuenteArp,
                    macVecinoDirecto,
                    StringComparison.OrdinalIgnoreCase))
            {
                RegistrarRespuestaArp(
                    arp.SenderProtocolAddress,
                    macFuenteArp);

                resultado.DireccionMac =
                    macFuenteArp;

                RegistrarOrigen("ARP");
                RegistrarFabricante(
                    _fabricanteMacService.ObtenerFabricante(
                        macFuenteArp));

                return;
            }

            uint ipRemota =
                ConvertirIPv4(arp.SenderProtocolAddress);

            if (objetivosArpActivos.Count > 0 &&
                !objetivosArpActivos.Contains(ipRemota))
            {
                return;
            }

            // En captura puramente pasiva solo aceptamos respuestas
            // dirigidas a la MAC de la PC.
            if (objetivosArpActivos.Count == 0 &&
                !EsNuestraMac(
                    ethernet.DestinationHardwareAddress))
            {
                return;
            }

            if (!string.IsNullOrWhiteSpace(
                    direccionIPObjetivo))
            {
                resultado.DireccionIP =
                    arp.SenderProtocolAddress.ToString();

                resultado.DireccionMac =
                    macFuenteArp;

                RegistrarOrigen("ARP");

                return;
            }

            RegistrarRespuestaArp(
                arp.SenderProtocolAddress,
                macFuenteArp);

            RegistrarOrigen("ARP");
            RegistrarFabricante(
                _fabricanteMacService.ObtenerFabricante(
                    macFuenteArp));
        }

        dispositivoSeleccionado.OnPacketArrival +=
            CuandoLlegaPaquete;

        dispositivoSeleccionado.Open(
            new DeviceConfiguration
            {
                Mode =
                    DeviceModes.Promiscuous,
                Immediate = true,
                ReadTimeout = 100
            });

        Console.WriteLine(
            $"Captura iniciada en: {dispositivoSeleccionado.Name}");

        try
        {
            // Comenzamos a escuchar antes de cualquier consulta.
            dispositivoSeleccionado.StartCapture();

            IPAddress direccionOrigenArp =
                direccionIpLocal ??
                IPAddress.Any;

            if (dispositivoSeleccionado is not IInjectionDevice dispositivoInyeccion)
            {
                throw new InvalidOperationException(
                    "El dispositivo de captura seleccionado no permite inyección de paquetes.");
            }

            if (!busquedaPorIp)
            {
                UltimaFaseDeteccion =
                    "Escuchando LLDP/CDP/EDP/FDP/NDP/HPSW/STP";

                // Fase 1: escuchamos sin enviar nada todavía. La mayoría
                // de los switches administrables emiten su primer anuncio
                // LLDP/CDP apenas detectan el enlace activo (no hace
                // falta esperar el ciclo periódico completo de 30-60s),
                // así que esta ventana corta suele alcanzar. Si el
                // vecino se identifica acá, es una detección confirmada
                // de un solo salto: no puede tratarse de otro equipo
                // más allá en la red, porque LLDP/CDP nunca se reenvían.
                await EsperarCondicionAsync(
                    () => vecinoDirectoDetectado,
                    TimeSpan.FromSeconds(6));

                if (vecinoDirectoDetectado)
                {
                    Console.WriteLine(
                        "Vecino directo confirmado por LLDP/CDP/EDP/FDP/STP antes de recurrir a ARP.");
                }
            }

            UltimaFaseDeteccion =
                busquedaPorIp
                    ? "Preparando ARP dirigido"
                    : "Preparando sondeo ARP";

            List<IPAddress> objetivosArpLocales =
                new List<IPAddress>();

            List<IPAddress> objetivosArpLinkLocal =
                new List<IPAddress>();

            List<IPAddress> objetivosArpRespaldo =
                new List<IPAddress>();

            if (busquedaPorIp)
            {
                objetivosArpLocales.Add(
                    IPAddress.Parse(
                        direccionIPObjetivo));
            }
            else
            {
                objetivosArpLocales =
                    ObtenerObjetivosRedLocal(
                        direccionIpLocal,
                        mascaraRedLocal,
                        puertaEnlace,
                        ipsHistoricas);

                objetivosArpLinkLocal =
                    ObtenerObjetivosLinkLocal(
                        direccionIpLocal);

                if (vecinoDirectoDetectado ||
                    busquedaPorMac)
                {
                    objetivosArpRespaldo =
                        ObtenerObjetivosRespaldo(
                            direccionIpLocal);
                }
            }

            List<IPAddress> objetivosArp =
                objetivosArpLocales
                    .Concat(objetivosArpLinkLocal)
                    .Concat(objetivosArpRespaldo)
                    .ToList();

            objetivosArpActivos.Clear();

            foreach (IPAddress objetivo in objetivosArp)
            {
                if (!EsDireccionValidaArp(
                        objetivo,
                        direccionIpLocal))
                {
                    continue;
                }

                objetivosArpActivos.Add(
                    ConvertirIPv4(objetivo));
            }

            UltimaCantidadSondasArp = 0;

            UltimaEstimacionDeteccionMs =
                busquedaPorIp
                    ? 1400
                    : 6000 +
                      (OperatingSystem.IsWindows()
                          ? EstimarDuracionArpOptimizadoMs(
                                objetivosArpLocales.Count,
                                objetivosArpLinkLocal.Count,
                                objetivosArpRespaldo.Count)
                          : EstimarDuracionArpMs(
                                objetivosArpLocales.Count,
                                objetivosArpLinkLocal.Count,
                                objetivosArpRespaldo.Count));

            // Si ya tenemos IP resuelta por LLDP/CDP en la fase 1, no
            // hace falta ningún ARP: ya sabemos que es el vecino directo.
            // Si el vecino se identificó pero todavía falta su IP (por
            // ejemplo, LLDP sin Management Address), sí conviene lanzar
            // el ARP: el filtro por MAC ya vigente solo va a aceptar la
            // respuesta que venga de esa misma MAC, así que sigue siendo
            // seguro aunque el ARP llegue hasta el gateway u otros
            // equipos. Si no hubo ningún vecino directo, el ARP pasa a
            // ser el único recurso disponible y el resultado deja de
            // tener la misma garantía de "un solo salto": lo indicamos
            // Si solo tenemos ARP, no existe confirmación física del
            // vecino. Las respuestas se consolidan y se puntúan para
            // escoger el candidato con mayor evidencia disponible.
            if (busquedaPorIp)
            {
                Console.WriteLine(
                    $"Detección dirigida iniciada para {direccionIPObjetivo}.");

                IPAddress objetivo =
                    IPAddress.Parse(
                        direccionIPObjetivo);

                UltimaFaseDeteccion =
                    "ARP dirigido";

                for (int intento = 1;
                     intento <= 3 &&
                     string.IsNullOrWhiteSpace(
                         resultado.DireccionIP);
                     intento++)
                {
                    EnviarConsultaArp(
                        dispositivoInyeccion,
                        direccionMacLocal,
                        direccionMacBroadcast,
                        direccionMacVacia,
                        objetivo,
                        direccionOrigenArp);

                    Interlocked.Increment(
                        ref _sondasArpActuales);

                    await Task.Delay(100);
                }
            }
            else if (!vecinoDirectoDetectado ||
                     string.IsNullOrWhiteSpace(
                         resultado.DireccionIP))
            {
                Console.WriteLine(
                    busquedaPorMac
                        ? $"Búsqueda por MAC iniciada para {macObjetivoNormalizada}. Sondas: {objetivosArpActivos.Count}."
                        : $"Sin confirmación LLDP/CDP/EDP/FDP/STP: recurriendo a ARP. Sondas: {objetivosArpActivos.Count}.");

                UltimaFaseDeteccion =
                    busquedaPorMac
                        ? "Búsqueda por MAC mediante ARP"
                        : "Sondeo ARP paralelo: red local + 169.254/16";

                SemaphoreSlim semaforoEnvioArp =
                    new SemaphoreSlim(1, 1);

                Task tareaRedLocal =
                    SondearArpAsync(
                        dispositivoInyeccion,
                        objetivosArpLocales,
                        direccionIpLocal,
                        direccionMacLocal,
                        direccionMacBroadcast,
                        direccionMacVacia,
                        direccionOrigenArp,
                        2,
                        semaforoEnvioArp);

                Task tareaLinkLocal =
                    SondearArpLinkLocalAdaptativoAsync(
                        dispositivoInyeccion,
                        objetivosArpLinkLocal,
                        direccionIpLocal,
                        direccionMacLocal,
                        direccionMacBroadcast,
                        direccionMacVacia,
                        direccionOrigenArp,
                        semaforoEnvioArp,
                        respuestasArp);

                Task tareaRespaldo =
                    SondearArpAsync(
                        dispositivoInyeccion,
                        objetivosArpRespaldo,
                        direccionIpLocal,
                        direccionMacLocal,
                        direccionMacBroadcast,
                        direccionMacVacia,
                        direccionOrigenArp,
                        objetivosArpLinkLocal.Count > 0
                            ? 2
                            : 1,
                        semaforoEnvioArp);

                await Task.WhenAll(
                    tareaRedLocal,
                    tareaLinkLocal,
                    tareaRespaldo);

                semaforoEnvioArp.Dispose();
            }
            else
            {
                Console.WriteLine(
                    "IP resuelta por LLDP/CDP/EDP/FDP/STP; se omite el escaneo ARP.");
            }

            if (objetivosArpActivos.Count == 0)
            {
                Console.WriteLine(
                    "No se generaron objetivos ARP automáticos. " +
                    "Se continuará únicamente con LLDP, CDP, EDP, FDP, NDP/HPSW, STP y captura pasiva.");
            }

            UltimaFaseDeteccion =
                "Consolidando respuestas";

            if (!busquedaPorIp)
            {
                await Task.Delay(500);

                if (string.IsNullOrWhiteSpace(
                        resultado.DireccionIP))
                {
                    if (busquedaPorMac)
                    {
                        ResolverResultadoArpPorMac(
                            resultado,
                            respuestasArp,
                            macObjetivoNormalizada,
                            vecinoDirectoDetectado,
                            puertaEnlace,
                            ipsHistoricas,
                            macsHistoricas,
                            usoMacDelHistorial);
                    }
                    else
                    {
                        ResolverResultadoArpAutomatico(
                            resultado,
                            respuestasArp,
                            vecinoDirectoDetectado,
                            macVecinoDirecto,
                            puertaEnlace,
                            ipsHistoricas,
                            macsHistoricas);
                    }
                }
            }
        
        if (usoMacDelHistorial &&
            string.IsNullOrWhiteSpace(resultado.DireccionIP) &&
            !string.IsNullOrWhiteSpace(direccionIPObjetivo))
        {
            UltimaFaseDeteccion =
                "ARP dirigido por IP del historial";

            busquedaPorMac = false;

            IPAddress objetivoHistorial =
                IPAddress.Parse(
                    direccionIPObjetivo);

            objetivosArpActivos.Add(
                ConvertirIPv4(
                    objetivoHistorial));

            for (int intento = 1;
                 intento <= 3 &&
                 string.IsNullOrWhiteSpace(
                     resultado.DireccionIP);
                 intento++)
            {
                EnviarConsultaArp(
                    dispositivoInyeccion,
                    direccionMacLocal,
                    direccionMacBroadcast,
                    direccionMacVacia,
                    objetivoHistorial,
                    direccionOrigenArp);

                Interlocked.Increment(
                    ref _sondasArpActuales);

                await Task.Delay(100);
            }

            busquedaPorMac = true;

            if (!string.IsNullOrWhiteSpace(
                    resultado.DireccionIP))
            {
                UltimoCriterioBusqueda =
                    "Historial → IP fallback";
            }
        }

        }

        finally
        {
            dispositivoSeleccionado.StopCapture();

            dispositivoSeleccionado.OnPacketArrival -=
                CuandoLlegaPaquete;

            dispositivoSeleccionado.Close();

            Console.WriteLine("Captura finalizada.");
        }

        UltimoOrigenDeteccion =
            origenDeteccion;

        UltimaFaseDeteccion =
            string.IsNullOrWhiteSpace(
                resultado.DireccionIP)
                ? "Sin resultado"
                : "Detección finalizada";

        cronometro.Stop();

        UltimaCantidadSondasArp =
            Volatile.Read(
                ref _sondasArpActuales);

        UltimaDuracionDeteccionMs =
            cronometro.ElapsedMilliseconds;

        if (string.IsNullOrWhiteSpace(resultado.DireccionMac))
        {
            Console.WriteLine(
                "No se identificó ningún vecino durante la detección.");
        }
        else
        {
            Console.WriteLine(
                $"Dispositivo identificado | " +
                $"IP: {resultado.DireccionIP} | " +
                $"MAC: {resultado.DireccionMac} | " +
                $"Nombre: {resultado.Nombre} | " +
                $"Origen: {UltimoOrigenDeteccion}");

            await _historialDispositivosService.RegistrarAsync(
                new RegistroDispositivo
                {
                    DireccionIP = resultado.DireccionIP,
                    DireccionMac = resultado.DireccionMac,
                    Nombre = resultado.Nombre,
                    NombreInterfaz = nombreInterfaz,
                    Origen = string.IsNullOrWhiteSpace(
                        origenDeteccion)
                        ? "Desconocido"
                        : origenDeteccion,
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
    /// Busca una trama EDP dentro de los bytes crudos del frame
    /// (LLC/SNAP con OUI Extreme 00-E0-2B y PID 0x00BB).
    /// Extrae Device-ID y la primera dirección IPv4 del Address TLV.
    /// </summary>
    private bool IntentarExtraerInformacionEdp(
        byte[] datos,
        out string macOrigen,
        out string nombreDispositivo,
        out string direccionGestion)
    {
        macOrigen = null;
        nombreDispositivo = null;
        direccionGestion = null;

        if (datos == null ||
            datos.Length < 54)
        {
            return false;
        }

        int inicioLlc = 14;

        ushort longitudEthernet =
            (ushort)((datos[12] << 8) | datos[13]);

        // EDP usa Ethernet 802.3 + LLC/SNAP. La etiqueta VLAN,
        // cuando existe, desplaza el LLC cuatro bytes.
        if (longitudEthernet == 0x8100 ||
            longitudEthernet == 0x88A8)
        {
            if (datos.Length < 58)
            {
                return false;
            }

            inicioLlc = 18;
        }

        if (datos[inicioLlc] != 0xAA ||
            datos[inicioLlc + 1] != 0xAA ||
            datos[inicioLlc + 2] != 0x03 ||
            datos[inicioLlc + 3] != 0x00 ||
            datos[inicioLlc + 4] != 0xE0 ||
            datos[inicioLlc + 5] != 0x2B ||
            datos[inicioLlc + 6] != 0x00 ||
            datos[inicioLlc + 7] != 0xBB)
        {
            return false;
        }

        int inicioEdp =
            inicioLlc + 8;

        if (inicioEdp + 16 > datos.Length)
        {
            return false;
        }

        macOrigen =
            FormatearMac(
                new PhysicalAddress(
                    datos.Skip(
                            inicioEdp + 10)
                        .Take(6)
                        .ToArray()));

        if (inicioEdp + 16 > datos.Length)
        {
            return false;
        }

        ushort longitudEdp =
            (ushort)((datos[inicioEdp + 2] << 8) |
                     datos[inicioEdp + 3]);

        int fin =
            Math.Min(
                datos.Length,
                inicioEdp + longitudEdp);

        if (fin <= inicioEdp + 16)
        {
            return false;
        }

        int posicion =
            inicioEdp + 16;

        while (posicion + 4 <= fin)
        {
            if (datos[posicion] != 0x99)
            {
                break;
            }

            int tipo =
                datos[posicion + 1];

            int longitud =
                (datos[posicion + 2] << 8) |
                datos[posicion + 3];

            if (longitud < 4 ||
                posicion + longitud > fin)
            {
                break;
            }

            int inicioValor =
                posicion + 4;

            int longitudValor =
                longitud - 4;

            // Display TLV: nombre del equipo.
            if (tipo == 0x01 &&
                longitudValor > 0 &&
                string.IsNullOrWhiteSpace(
                    nombreDispositivo))
            {
                nombreDispositivo =
                    System.Text.Encoding.ASCII.GetString(
                        datos,
                        inicioValor,
                        longitudValor)
                    .TrimEnd('\0', ' ');
            }

            // VLAN TLV: contiene la IP de la interfaz VLAN.
            if (tipo == 0x05 &&
                longitudValor >= 12)
            {
                byte flags =
                    datos[inicioValor];

                if ((flags & 0x80) != 0)
                {
                    IPAddress ip =
                        new IPAddress(
                            new byte[]
                            {
                                datos[inicioValor + 8],
                                datos[inicioValor + 9],
                                datos[inicioValor + 10],
                                datos[inicioValor + 11]
                            });

                    if (!EsDireccionEspecial(ip))
                    {
                        direccionGestion =
                            ip.ToString();

                        return true;
                    }
                }
            }

            if (tipo == 0x00)
            {
                break;
            }

            posicion += longitud;
        }

        return true;
    }

    /// <summary>
    /// Detecta el HP Switch Protocol (HPSW) legacy encapsulado en
    /// HP Extended LLC y extrae los datos seguros para identificación:
    /// MAC del equipo, nombre y una posible IPv4.
    /// </summary>
    private bool IntentarExtraerInformacionHpsw(
        byte[] datos,
        out string macOrigen,
        out string nombreDispositivo,
        out string direccionGestion)
    {
        macOrigen = null;
        nombreDispositivo = null;
        direccionGestion = null;

        // El encabezado Ethernet (14) + LLC (3) + HPEXT (7)
        // + version/type (2) requiere al menos 26 bytes.
        if (datos == null ||
            datos.Length < 26)
        {
            return false;
        }

        ushort longitudEthernet =
            (ushort)((datos[12] << 8) | datos[13]);

        // HPSW usa una trama IEEE 802.3 con longitud, no un EtherType.
        if (longitudEthernet == 0 ||
            longitudEthernet > 1500)
        {
            return false;
        }

        // DSAP/SSAP 0xF8 corresponden a HP Extended LLC.
        // El bit bajo del SSAP puede variar por command/response.
        if (datos[14] != 0xF8 ||
            (datos[15] & 0xFE) != 0xF8)
        {
            return false;
        }

        // El control LLC puede variar según el tipo de trama.
        // No lo fijamos a un valor concreto porque el dissector de
        // HP Extended LLC de Wireshark recibe el payload después del
        // encabezado LLC para distintos tipos de tramas de información.
        //
        // HPEXT:
        //   bytes 17-19 = reservado
        //   bytes 20-21 = DXSAP
        //   bytes 22-23 = SXSAP
        ushort dxsap =
            (ushort)((datos[20] << 8) | datos[21]);

        if (dxsap != 0x0623)
        {
            return false;
        }

        macOrigen =
            FormatearMac(
                new PhysicalAddress(
                    datos.Skip(6).Take(6).ToArray()));

        int posicion = 24;

        // En HPSW los primeros dos bytes son Version y Type.
        // Después comienza una secuencia de TLV de 1 byte de tipo +
        // 1 byte de longitud + valor.
        posicion += 2;

        while (posicion + 2 <= datos.Length)
        {
            int tipo =
                datos[posicion];

            int longitud =
                datos[posicion + 1];

            posicion += 2;

            if (longitud < 1 ||
                posicion + longitud > datos.Length)
            {
                break;
            }

            // Tipo 1 = Device Name.
            if (tipo == 0x01 &&
                string.IsNullOrWhiteSpace(
                    nombreDispositivo))
            {
                nombreDispositivo =
                    System.Text.Encoding.ASCII.GetString(
                        datos,
                        posicion,
                        longitud)
                    .TrimEnd(' ', ' ');
            }

            // Tipo 5 = IP Address.
            if (tipo == 0x05 &&
                longitud == 4)
            {
                IPAddress ip =
                    new IPAddress(
                        datos.AsSpan(
                                posicion,
                                4)
                            .ToArray());

                if (!EsDireccionEspecial(ip))
                {
                    direccionGestion =
                        ip.ToString();
                }
            }

            // Tipo 14 = Own MAC Address.
            // Preferimos esta MAC cuando está presente porque HPSW la
            // publica explícitamente como identidad del equipo.
            if (tipo == 0x0E &&
                longitud == 6)
            {
                macOrigen =
                    FormatearMac(
                        new PhysicalAddress(
                            datos.AsSpan(
                                    posicion,
                                    6)
                                .ToArray()));
            }

            posicion += longitud;
        }

        return true;
    }

    /// <summary>
    /// Detecta una trama de HGMPv2 asociada al mecanismo NDP legacy de
    /// H3C/3Com. La documentación de H3C permite una dirección multicast
    /// por defecto 01:80:C2:00:00:0A y también otras del rango
    /// 01:80:C2:00:00:20-2F.
    ///
    /// No interpreta el payload interno en esta etapa. La trama se usa
    /// como señal de vecino local y su MAC de origen se emplea para
    /// restringir el ARP posterior a ese mismo equipo.
    /// </summary>
    private bool IntentarExtraerInformacionNdp(
        byte[] datos,
        out string macOrigen)
    {
        macOrigen = null;

        if (datos == null ||
            datos.Length < 14)
        {
            return false;
        }

        // HGMPv2 usa el espacio de multicast documentado por H3C.
        if (!EsDireccionMacHgmp(
                datos,
                0))
        {
            return false;
        }

        macOrigen =
            FormatearMac(
                new PhysicalAddress(
                    datos.Skip(6).Take(6).ToArray()));

        if (string.IsNullOrWhiteSpace(macOrigen))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Comprueba si los seis bytes de una posición corresponden a una
    /// dirección multicast reservada por HGMPv2/NDP.
    /// </summary>
    private bool EsDireccionMacHgmp(
        byte[] datos,
        int posicion)
    {
        if (datos == null ||
            posicion < 0 ||
            posicion + 6 > datos.Length)
        {
            return false;
        }

        // 01:80:C2:00:00:0A es la dirección multicast HGMPv2/NDP
        // documentada por H3C como valor predeterminado.
        if (datos[posicion] == 0x01 &&
            datos[posicion + 1] == 0x80 &&
            datos[posicion + 2] == 0xC2 &&
            datos[posicion + 3] == 0x00 &&
            datos[posicion + 4] == 0x00 &&
            datos[posicion + 5] == 0x0A)
        {
            return true;
        }

        // H3C permite configurar otras direcciones dentro de
        // 01:80:C2:00:00:20-2F para los paquetes HGMPv2.
        return datos[posicion] == 0x01 &&
               datos[posicion + 1] == 0x80 &&
               datos[posicion + 2] == 0xC2 &&
               datos[posicion + 3] == 0x00 &&
               datos[posicion + 4] == 0x00 &&
               datos[posicion + 5] >= 0x20 &&
               datos[posicion + 5] <= 0x2F;
    }

    private bool IntentarExtraerInformacionFdp(
        byte[] datos,
        out string macOrigen,
        out string nombreDispositivo,
        out string direccionGestion)
    {
        macOrigen = null;
        nombreDispositivo = null;
        direccionGestion = null;

        if (datos == null ||
            datos.Length < 30)
        {
            return false;
        }

        int inicioLlc = 14;

        ushort longitud =
            (ushort)((datos[12] << 8) | datos[13]);

        if (longitud > 1500)
        {
            return false;
        }

        // FDP: LLC/SNAP, OUI Foundry 00:E0:52, PID 0x2000.
        if (datos[inicioLlc] != 0xAA ||
            datos[inicioLlc + 1] != 0xAA ||
            datos[inicioLlc + 2] != 0x03 ||
            datos[inicioLlc + 3] != 0x00 ||
            datos[inicioLlc + 4] != 0xE0 ||
            datos[inicioLlc + 5] != 0x52 ||
            datos[inicioLlc + 6] != 0x20 ||
            datos[inicioLlc + 7] != 0x00)
        {
            return false;
        }

        macOrigen =
            FormatearMac(
                new PhysicalAddress(
                    datos.Skip(6).Take(6).ToArray()));

        int inicioFdp =
            inicioLlc + 8;

        if (inicioFdp + 4 > datos.Length)
        {
            return false;
        }

        int posicion =
            inicioFdp + 4;

        while (posicion + 4 <= datos.Length)
        {
            int tipo =
                (datos[posicion] << 8) |
                datos[posicion + 1];

            int longitudTlv =
                (datos[posicion + 2] << 8) |
                datos[posicion + 3];

            if (longitudTlv < 4 ||
                posicion + longitudTlv > datos.Length)
            {
                break;
            }

            int inicioValor =
                posicion + 4;

            int longitudValor =
                longitudTlv - 4;

            if (tipo == 1 &&
                longitudValor > 0)
            {
                nombreDispositivo =
                    System.Text.Encoding.ASCII.GetString(
                        datos,
                        inicioValor,
                        longitudValor)
                    .TrimEnd('\0', ' ');
            }

            if (tipo == 2 &&
                longitudValor >= 13)
            {
                int bytesIp =
                    (datos[inicioValor + 7] << 8) |
                    datos[inicioValor + 8];

                int posicionIp =
                    inicioValor + 9;

                int limiteIp =
                    Math.Min(
                        inicioValor + longitudValor,
                        posicionIp + bytesIp);

                while (posicionIp + 4 <= limiteIp)
                {
                    IPAddress ip =
                        new IPAddress(
                            datos.AsSpan(
                                    posicionIp,
                                    4)
                                .ToArray());

                    if (!EsDireccionEspecial(
                            ip))
                    {
                        direccionGestion =
                            ip.ToString();

                        break;
                    }

                    posicionIp += 4;
                }
            }

            posicion += longitudTlv;
        }

        return true;
    }

    private bool EsDireccionEspecial(
        IPAddress direccionIP)
    {
        if (direccionIP == null ||
            direccionIP.AddressFamily !=
                AddressFamily.InterNetwork)
        {
            return true;
        }

        if (direccionIP.Equals(
                IPAddress.Any) ||
            direccionIP.Equals(
                IPAddress.Broadcast) ||
            direccionIP.Equals(
                IPAddress.Loopback))
        {
            return true;
        }

        byte[] bytes =
            direccionIP.GetAddressBytes();

        return bytes[0] >= 224;
    }

    private bool IntentarExtraerInformacionStp(
        byte[] datos,
        out string macOrigen)
    {
        macOrigen = null;

        if (datos == null ||
            datos.Length < 20)
        {
            return false;
        }

        int inicioLlc = 14;

        ushort tipoEthernet =
            (ushort)((datos[12] << 8) | datos[13]);

        if (tipoEthernet == 0x8100 ||
            tipoEthernet == 0x88A8)
        {
            if (datos.Length < 24)
            {
                return false;
            }

            inicioLlc = 18;
        }

        if (datos[inicioLlc] != 0x42 ||
            datos[inicioLlc + 1] != 0x42 ||
            datos[inicioLlc + 2] != 0x03)
        {
            return false;
        }

        int inicioBpdu =
            inicioLlc + 3;

        if (inicioBpdu + 4 > datos.Length)
        {
            return false;
        }

        ushort protocolo =
            (ushort)((datos[inicioBpdu] << 8) |
                     datos[inicioBpdu + 1]);

        byte version =
            datos[inicioBpdu + 2];

        byte tipoBpdu =
            datos[inicioBpdu + 3];

        if (protocolo != 0x0000 ||
            version > 3 ||
            (tipoBpdu != 0x00 &&
             tipoBpdu != 0x02))
        {
            return false;
        }

        macOrigen =
            FormatearMac(
                new PhysicalAddress(
                    datos.Skip(6).Take(6).ToArray()));

        return true;
    }

    private void IntentarExtraerInformacionCdp(
        byte[] datos,
        out string macOrigen,
        out string nombreDispositivo,
        out string direccionGestion)
    {
        macOrigen = null;
        nombreDispositivo = null;
        direccionGestion = null;

        const int longitudMinima = 26;

        if (datos == null ||
            datos.Length < longitudMinima)
        {
            return;
        }

        if (datos[14] != 0xAA ||
            datos[15] != 0xAA ||
            datos[16] != 0x03)
        {
            return;
        }

        if (datos[17] != 0x00 ||
            datos[18] != 0x00 ||
            datos[19] != 0x0C ||
            datos[20] != 0x20 ||
            datos[21] != 0x00)
        {
            return;
        }

        macOrigen =
            FormatearMac(
                new PhysicalAddress(
                    datos.Skip(6).Take(6).ToArray()));

        int posicion = 26;

        while (posicion + 4 <= datos.Length)
        {
            int tipoTlv =
                (datos[posicion] << 8) |
                datos[posicion + 1];

            int longitudTlv =
                (datos[posicion + 2] << 8) |
                datos[posicion + 3];

            if (longitudTlv < 4 ||
                posicion + longitudTlv > datos.Length)
            {
                break;
            }

            int inicioValor =
                posicion + 4;

            int longitudValor =
                longitudTlv - 4;

            // 0x0001 = Device-ID.
            if (tipoTlv == 0x0001 &&
                longitudValor > 0)
            {
                nombreDispositivo =
                    System.Text.Encoding.ASCII.GetString(
                        datos,
                        inicioValor,
                        longitudValor)
                    .TrimEnd('\0');
            }

            // 0x0002 = Address TLV. El valor comienza con la cantidad
            // de direcciones y luego cada dirección contiene protocolo,
            // longitud del protocolo, valor del protocolo, longitud de
            // dirección y los bytes de la dirección.
            if ((tipoTlv == 0x0002 ||
                 tipoTlv == 0x0016) &&
                longitudValor >= 4)
            {
                direccionGestion =
                    ExtraerDireccionIpv4CdpAddressTlv(
                        datos,
                        inicioValor,
                        longitudValor);
            }

            posicion += longitudTlv;
        }
    }

    private string ExtraerDireccionIpv4CdpAddressTlv(
        byte[] datos,
        int inicio,
        int longitud)
    {
        if (inicio < 0 ||
            longitud < 4 ||
            inicio + longitud > datos.Length)
        {
            return null;
        }

        int cantidadDirecciones =
            (datos[inicio] << 24) |
            (datos[inicio + 1] << 16) |
            (datos[inicio + 2] << 8) |
            datos[inicio + 3];

        int posicion =
            inicio + 4;

        int fin =
            inicio + longitud;

        for (int indice = 0;
             indice < cantidadDirecciones &&
             posicion + 4 <= fin;
             indice++)
        {
            int tipoProtocolo =
                datos[posicion];

            int longitudProtocolo =
                datos[posicion + 1];

            posicion += 2;

            if (posicion + longitudProtocolo + 2 > fin)
            {
                break;
            }

            byte[] protocolo =
                datos.AsSpan(
                        posicion,
                        longitudProtocolo)
                    .ToArray();

            posicion += longitudProtocolo;

            int longitudDireccion =
                (datos[posicion] << 8) |
                datos[posicion + 1];

            posicion += 2;

            if (posicion + longitudDireccion > fin)
            {
                break;
            }

            // NLPID 0x01 + protocolo IP y longitud de dirección 4
            // corresponde a una dirección IPv4 en el formato observado
            // por CDP.
            if (tipoProtocolo == 0x01 &&
                longitudProtocolo == 1 &&
                protocolo[0] == 0xCC &&
                longitudDireccion == 4)
            {
                return new IPAddress(
                    datos.AsSpan(
                            posicion,
                            4)
                        .ToArray())
                    .ToString();
            }

            posicion += longitudDireccion;
        }

        return null;
    }

    private void ResolverResultadoArpPorMac(
        DispositivoDetectado resultado,
        Dictionary<uint, Dictionary<string, int>> respuestasArp,
        string macObjetivoNormalizada,
        bool vecinoDirectoDetectado,
        IPAddress puertaEnlace,
        HashSet<string> ipsHistoricas,
        HashSet<string> macsHistoricas,
        bool usoMacDelHistorial)
    {
        List<(uint ip, string mac, int respuestas, string fabricante, int puntaje)> candidatos =
            new List<(uint ip, string mac, int respuestas, string fabricante, int puntaje)>();

        foreach (KeyValuePair<uint, Dictionary<string, int>> respuesta
                 in respuestasArp)
        {
            foreach (KeyValuePair<string, int> mac
                     in respuesta.Value)
            {
                if (!string.Equals(
                        mac.Key,
                        macObjetivoNormalizada,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                IPAddress ip =
                    ConvertirAIPv4(
                        respuesta.Key);

                string fabricante =
                    _fabricanteMacService.ObtenerFabricante(
                        mac.Key);

                bool ipHistorica =
                    ipsHistoricas.Contains(
                        ip.ToString());

                bool macHistorica =
                    macsHistoricas.Contains(
                        mac.Key);

                int puntaje =
                    CalcularPuntajeArp(
                        ip,
                        mac.Key,
                        mac.Value,
                        puertaEnlace,
                        fabricante,
                        vecinoDirectoDetectado,
                        ipHistorica,
                        macHistorica);

                candidatos.Add(
                    (respuesta.Key,
                     mac.Key,
                     mac.Value,
                     fabricante,
                     puntaje));
            }
        }

        if (candidatos.Count == 0)
        {
            return;
        }

        bool huboCoincidenciaMacVecino =
            vecinoDirectoDetectado &&
            candidatos.Any(
                candidato =>
                    string.Equals(
                        candidato.mac,
                        macVecinoDirecto,
                        StringComparison.OrdinalIgnoreCase));

        List<(uint ip, string mac, int respuestas, string fabricante, int puntaje)> candidatosParaResolver =
            huboCoincidenciaMacVecino
                ? candidatos
                    .Where(
                        candidato =>
                            string.Equals(
                                candidato.mac,
                                macVecinoDirecto,
                                StringComparison.OrdinalIgnoreCase))
                    .ToList()
                : candidatos;

        List<(uint ip, string mac, int respuestas, string fabricante, int puntaje)> ordenados =
            candidatosParaResolver
                .OrderByDescending(
                    candidato => candidato.puntaje)
                .ThenByDescending(
                    candidato => candidato.respuestas)
                .ThenBy(
                    candidato => candidato.ip)
                .ToList();

        var mejor =
            ordenados[0];

        int segundoPuntaje =
            ordenados.Count > 1
                ? ordenados[1].puntaje
                : 0;

        int diferencia =
            mejor.puntaje -
            segundoPuntaje;

        UltimoPuntajeDeteccion =
            mejor.puntaje;

        UltimoFabricanteDeteccion =
            mejor.fabricante;

        resultado.DireccionIP =
            ConvertirAIPv4(
                mejor.ip)
            .ToString();

        resultado.DireccionMac =
            mejor.mac;

        if (ordenados.Count == 1 &&
            vecinoDirectoDetectado)
        {
            UltimaConfianzaDeteccion =
                "Confirmado por vecino directo";
        }
        else if (ordenados.Count == 1)
        {
            UltimaConfianzaDeteccion =
                usoMacDelHistorial
                    ? "Confirmado por MAC del historial"
                    : "Confirmado por MAC objetivo";
        }
        else if (diferencia >= 12 &&
                 mejor.puntaje >= 55)
        {
            UltimaConfianzaDeteccion =
                "MAC confirmada; IP probable por evidencia ARP";
        }
        else
        {
            UltimaConfianzaDeteccion =
                "MAC confirmada; IP seleccionada entre múltiples candidatas";
        }

        UltimaRazonDeteccion =
            $"La MAC objetivo coincidió con {ordenados.Count} IPv4 candidata(s). " +
            $"Se seleccionó {resultado.DireccionIP} con {mejor.puntaje} puntos " +
            $"y {mejor.respuestas} respuesta(s).";

        if (diferencia < 12 &&
            ordenados.Count > 1)
        {
            UltimaRazonDeteccion +=
                " Las candidatas quedaron muy próximas y la elección es probabilística.";
        }

        if (ipsHistoricas.Contains(
                resultado.DireccionIP))
        {
            UltimaRazonDeteccion +=
                " La IP apareció en el historial de esta interfaz.";
        }

        if (macsHistoricas.Contains(
                mejor.mac))
        {
            UltimaRazonDeteccion +=
                " La MAC apareció en el historial de esta interfaz.";
        }
    }

    private void ResolverResultadoArpAutomatico(
        DispositivoDetectado resultado,
        Dictionary<uint, Dictionary<string, int>> respuestasArp,
        bool vecinoDirectoDetectado,
        string macVecinoDirecto,
        IPAddress puertaEnlace,
        HashSet<string> ipsHistoricas,
        HashSet<string> macsHistoricas)
    {
        List<(uint ip, string mac, int respuestas, string fabricante, int puntaje)> candidatos =
            new List<(uint ip, string mac, int respuestas, string fabricante, int puntaje)>();

        foreach (KeyValuePair<uint, Dictionary<string, int>> respuesta
                 in respuestasArp)
        {
            foreach (KeyValuePair<string, int> mac
                     in respuesta.Value)
            {
                if (vecinoDirectoDetectado &&
                    !string.Equals(
                        mac.Key,
                        macVecinoDirecto,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                IPAddress ip =
                    ConvertirAIPv4(
                        respuesta.Key);

                string fabricante =
                    _fabricanteMacService.ObtenerFabricante(
                        mac.Key);

                bool ipHistorica =
                    ipsHistoricas.Contains(
                        ip.ToString());

                bool macHistorica =
                    macsHistoricas.Contains(
                        mac.Key);

                int puntaje =
                    CalcularPuntajeArp(
                        ip,
                        mac.Key,
                        mac.Value,
                        puertaEnlace,
                        fabricante,
                        vecinoDirectoDetectado,
                        ipHistorica,
                        macHistorica);

                candidatos.Add(
                    (respuesta.Key,
                     mac.Key,
                     mac.Value,
                     fabricante,
                     puntaje));
            }
        }

        if (candidatos.Count == 0)
        {
            return;
        }

        List<(uint ip, string mac, int respuestas, string fabricante, int puntaje)> ordenados =
            candidatos
                .OrderByDescending(
                    candidato => candidato.puntaje)
                .ThenByDescending(
                    candidato => candidato.respuestas)
                .ThenBy(
                    candidato => candidato.ip)
                .ToList();

        var mejor =
            ordenados[0];

        int segundoPuntaje =
            ordenados.Count > 1
                ? ordenados[1].puntaje
                : 0;

        int diferencia =
            mejor.puntaje -
            segundoPuntaje;

        UltimoPuntajeDeteccion =
            mejor.puntaje;

        UltimoFabricanteDeteccion =
            mejor.fabricante;

        // Siempre elegimos el candidato con mayor evidencia disponible.
        // La confianza indica si la IP es confirmada, probable o solo la
        // mejor opción heurística. Esto evita resultados nulos cuando ARP
        // sí obtuvo información, sin presentar la heurística como certeza.
        resultado.DireccionIP =
            ConvertirAIPv4(
                mejor.ip)
            .ToString();

        resultado.DireccionMac =
            mejor.mac;

        if (vecinoDirectoDetectado &&
            huboCoincidenciaMacVecino)
        {
            UltimaConfianzaDeteccion =
                "Confirmado por vecino directo";
        }
        else if (vecinoDirectoDetectado &&
                 diferencia >= 12 &&
                 mejor.puntaje >= 55)
        {
            UltimaConfianzaDeteccion =
                "Vecino L2 confirmado; IP probable por ARP";
        }
        else if (diferencia >= 12 &&
                 mejor.puntaje >= 55)
        {
            UltimaConfianzaDeteccion =
                "Probable por heurística ARP";
        }
        else if (mejor.puntaje >= 30)
        {
            UltimaConfianzaDeteccion =
                "Posible: candidato más probable";
        }
        else
        {
            UltimaConfianzaDeteccion =
                "Baja: candidato más probable";
        }

        UltimaRazonDeteccion =
            $"Se seleccionó el candidato con mayor evidencia: " +
            $"{mejor.puntaje} puntos, " +
            $"{mejor.respuestas} respuesta(s), " +
            $"fabricante: {mejor.fabricante}.";

        if (vecinoDirectoDetectado &&
            !huboCoincidenciaMacVecino)
        {
            UltimaRazonDeteccion +=
                " La MAC anunciada por el protocolo L2 no apareció en ARP; " +
                "se amplió la selección a las candidatas ARP para recuperar la IPv4.";
        }

        if (diferencia < 12 &&
            ordenados.Count > 1)
        {
            UltimaRazonDeteccion +=
                " Otros candidatos quedaron muy cerca.";
        }

        if (ipsHistoricas.Contains(
                ConvertirAIPv4(mejor.ip).ToString()))
        {
            UltimaRazonDeteccion +=
                " La IP apareció en el historial de esta interfaz.";
        }

        if (macsHistoricas.Contains(
                mejor.mac))
        {
            UltimaRazonDeteccion +=
                " La MAC apareció en el historial de esta interfaz.";
        }
    }

    private int CalcularPuntajeArp(
        IPAddress direccionIP,
        string direccionMac,
        int respuestas,
        IPAddress puertaEnlace,
        string fabricante,
        bool vecinoDirectoDetectado,
        bool ipHistorica,
        bool macHistorica)
    {
        int puntaje =
            Math.Min(
                respuestas * 15,
                45);

        if (puertaEnlace != null &&
            direccionIP.Equals(
                puertaEnlace))
        {
            puntaje += 35;
        }

        if (EsDireccionGestionComun(
                direccionIP))
        {
            puntaje += 25;
        }

        if (_fabricanteMacService.EsFabricanteInfraestructura(
                direccionMac))
        {
            puntaje += 25;
        }

        if (vecinoDirectoDetectado)
        {
            puntaje += 40;
        }

        byte ultimoOcteto =
            direccionIP.GetAddressBytes()[3];

        if (ultimoOcteto == 1 ||
            ultimoOcteto == 254)
        {
            puntaje += 15;
        }

        if (direccionIP.GetAddressBytes()[0] == 169 &&
            direccionIP.GetAddressBytes()[1] == 254)
        {
            puntaje += 5;
        }

        if (ipHistorica)
        {
            puntaje += 25;
        }

        if (macHistorica)
        {
            puntaje += 35;
        }

        return puntaje;
    }

    private bool EsDireccionGestionComun(
        IPAddress direccionIP)
    {
        return ObtenerDireccionesGestionProbables()
            .Contains(
                direccionIP.ToString(),
                StringComparer.OrdinalIgnoreCase);
    }

    private IEnumerable<string> ObtenerDireccionesGestionProbables()
    {
        return new[]
        {
            "192.168.0.1",
            "192.168.0.254",
            "192.168.1.1",
            "192.168.1.254",
            "192.168.100.1",
            "192.168.100.254",
            "10.0.0.1",
            "10.0.0.254",
            "10.0.1.1",
            "10.0.1.254",
            "172.16.0.1",
            "172.16.0.254"
        };
    }

    private List<IPAddress> ObtenerObjetivosRedLocal(
        IPAddress direccionIpLocal,
        IPAddress mascaraRedLocal,
        IPAddress puertaEnlace,
        HashSet<string> ipsHistoricas)
    {
        List<IPAddress> objetivos =
            new List<IPAddress>();

        HashSet<uint> vistos =
            new HashSet<uint>();

        void Agregar(IPAddress direccion)
        {
            if (!EsDireccionValidaArp(
                    direccion,
                    direccionIpLocal))
            {
                return;
            }

            uint valor =
                ConvertirIPv4(direccion);

            if (vistos.Add(valor))
            {
                objetivos.Add(direccion);
            }
        }

        Agregar(puertaEnlace);

        foreach (string candidato in ObtenerDireccionesGestionProbables())
        {
            Agregar(
                IPAddress.Parse(
                    candidato));
        }

        foreach (string ipHistorica in
                 ipsHistoricas.Take(128))
        {
            if (IPAddress.TryParse(
                    ipHistorica,
                    out IPAddress direccionHistorica))
            {
                Agregar(
                    direccionHistorica);
            }
        }

        if (direccionIpLocal == null ||
            mascaraRedLocal == null)
        {
            return objetivos;
        }

        uint ipLocal =
            ConvertirIPv4(direccionIpLocal);

        uint mascara =
            ConvertirIPv4(mascaraRedLocal);

        uint red =
            ipLocal & mascara;

        uint broadcast =
            red | ~mascara;

        ulong cantidadDirecciones =
            (ulong)broadcast -
            red +
            1UL;

        if (cantidadDirecciones == 2UL)
        {
            Agregar(
                ConvertirAIPv4(red));

            Agregar(
                ConvertirAIPv4(broadcast));

            return objetivos;
        }

        if (cantidadDirecciones > 65536UL)
        {
            return objetivos;
        }

        for (uint candidato = red + 1U;
             candidato < broadcast;
             candidato++)
        {
            if (candidato == ipLocal)
            {
                continue;
            }

            Agregar(
                ConvertirAIPv4(candidato));
        }

        return objetivos;
    }

    private List<IPAddress> ObtenerObjetivosLinkLocal(
        IPAddress direccionIpLocal)
    {
        List<IPAddress> objetivos =
            new List<IPAddress>();

        // RFC 3927 reserva 169.254.1.0 - 169.254.254.255
        // para selección de direcciones Link-Local.
        uint inicio =
            ConvertirIPv4(
                IPAddress.Parse(
                    "169.254.1.0"));

        uint fin =
            ConvertirIPv4(
                IPAddress.Parse(
                    "169.254.254.255"));

        for (uint candidato = inicio;
             candidato <= fin;
             candidato++)
        {
            IPAddress direccion =
                ConvertirAIPv4(candidato);

            if (direccionIpLocal != null &&
                direccion.Equals(direccionIpLocal))
            {
                continue;
            }

            objetivos.Add(
                direccion);
        }

        return objetivos;
    }

    private List<IPAddress> ObtenerObjetivosRespaldo(
        IPAddress direccionIpLocal)
    {
        List<IPAddress> objetivos =
            new List<IPAddress>();

        HashSet<uint> vistos =
            new HashSet<uint>();

        void AgregarRed(
            string direccionRed)
        {
            foreach (IPAddress direccion
                     in CrearObjetivosRedComun(
                         direccionIpLocal,
                         direccionRed))
            {
                uint valor =
                    ConvertirIPv4(direccion);

                if (vistos.Add(valor))
                {
                    objetivos.Add(direccion);
                }
            }
        }

        AgregarRed("10.0.0.0");
        AgregarRed("10.0.1.0");
        AgregarRed("192.168.0.0");
        AgregarRed("192.168.1.0");
        AgregarRed("192.168.100.0");
        AgregarRed("172.16.0.0");

        return objetivos;
    }

    private List<IPAddress> CrearObjetivosRedComun(
        IPAddress direccionIpLocal,
        string direccionRed)
    {
        List<IPAddress> objetivos =
            new List<IPAddress>();

        IPAddress red =
            IPAddress.Parse(
                direccionRed);

        uint baseRed =
            ConvertirIPv4(red);

        uint broadcast =
            baseRed | 0x000000FFU;

        AgregarObjetivo(
            objetivos,
            new HashSet<uint>(),
            ConvertirAIPv4(
                baseRed + 1U),
            direccionIpLocal);

        AgregarObjetivo(
            objetivos,
            new HashSet<uint>(),
            ConvertirAIPv4(
                broadcast - 1U),
            direccionIpLocal);

        for (uint candidato = baseRed + 1U;
             candidato < broadcast;
             candidato++)
        {
            if (candidato == baseRed + 1U ||
                candidato == broadcast - 1U)
            {
                continue;
            }

            AgregarObjetivo(
                objetivos,
                new HashSet<uint>(),
                ConvertirAIPv4(candidato),
                direccionIpLocal);
        }

        return objetivos;
    }

    private async Task SondearArpLinkLocalAdaptativoAsync(
        IInjectionDevice dispositivoInyeccion,
        List<IPAddress> objetivos,
        IPAddress direccionIpLocal,
        PhysicalAddress direccionMacLocal,
        PhysicalAddress direccionMacBroadcast,
        PhysicalAddress direccionMacVacia,
        IPAddress direccionOrigenArp,
        SemaphoreSlim semaforoEnvioArp,
        Dictionary<uint, Dictionary<string, int>> respuestasArp)
    {
        if (objetivos.Count == 0)
        {
            return;
        }

        // Primera pasada: cobertura completa de 169.254.1.0/24 hasta
        // 169.254.254.255. Las respuestas se observan simultáneamente.
        await SondearArpAsync(
            dispositivoInyeccion,
            objetivos,
            direccionIpLocal,
            direccionMacLocal,
            direccionMacBroadcast,
            direccionMacVacia,
            direccionOrigenArp,
            1,
            semaforoEnvioArp);

        await Task.Delay(300);

        List<IPAddress> candidatos =
            respuestasArp
                .Keys
                .Select(ConvertirAIPv4)
                .Where(direccion =>
                {
                    byte[] bytes =
                        direccion.GetAddressBytes();

                    return bytes[0] == 169 &&
                           bytes[1] == 254;
                })
                .ToList();

        if (candidatos.Count == 0)
        {
            return;
        }

        // Segunda pasada: solo IP que respondieron. Así comprobamos
        // consistencia sin repetir todo el /16.
        await SondearArpAsync(
            dispositivoInyeccion,
            candidatos,
            direccionIpLocal,
            direccionMacLocal,
            direccionMacBroadcast,
            direccionMacVacia,
            direccionOrigenArp,
            1,
            semaforoEnvioArp);
    }

    private async Task SondearArpAsync(
        IInjectionDevice dispositivoInyeccion,
        List<IPAddress> objetivos,
        IPAddress direccionIpLocal,
        PhysicalAddress direccionMacLocal,
        PhysicalAddress direccionMacBroadcast,
        PhysicalAddress direccionMacVacia,
        IPAddress direccionOrigenArp,
        int cantidadRondas,
        SemaphoreSlim semaforoEnvioArp)
    {
        if (objetivos.Count == 0)
        {
            return;
        }

        if (OperatingSystem.IsWindows() &&
            dispositivoInyeccion is PcapDevice dispositivoPcap)
        {
            await Task.Run(
                () => SondearArpConCola(
                    dispositivoPcap,
                    objetivos,
                    direccionIpLocal,
                    direccionMacLocal,
                    direccionOrigenArp,
                    cantidadRondas,
                    semaforoEnvioArp));

            return;
        }

        for (int ronda = 1;
             ronda <= cantidadRondas;
             ronda++)
        {
            int cantidadEnviada = 0;

            foreach (IPAddress objetivo in objetivos)
            {
                if (!EsDireccionValidaArp(
                        objetivo,
                        direccionIpLocal))
                {
                    continue;
                }

                await semaforoEnvioArp.WaitAsync();

                try
                {
                    EnviarConsultaArp(
                        dispositivoInyeccion,
                        direccionMacLocal,
                        direccionMacBroadcast,
                        direccionMacVacia,
                        objetivo,
                        direccionOrigenArp);

                    Interlocked.Increment(
                        ref _sondasArpActuales);
                }
                finally
                {
                    semaforoEnvioArp.Release();
                }

                cantidadEnviada++;

                if (cantidadEnviada % 256 == 0)
                {
                    await Task.Delay(10);
                }
            }

            UltimaCantidadSondasArp =
                Volatile.Read(
                    ref _sondasArpActuales);

            Console.WriteLine(
                $"Sondeo ARP {ronda}/{cantidadRondas}: " +
                $"{cantidadEnviada} solicitudes.");

            if (ronda < cantidadRondas)
            {
                await Task.Delay(700);
            }
        }
    }

    private void SondearArpConCola(
        PcapDevice dispositivoPcap,
        List<IPAddress> objetivos,
        IPAddress direccionIpLocal,
        PhysicalAddress direccionMacLocal,
        IPAddress direccionOrigenArp,
        int cantidadRondas,
        SemaphoreSlim semaforoEnvioArp)
    {
        const int tamanoCola =
            8 * 1024 * 1024;

        for (int ronda = 1;
             ronda <= cantidadRondas;
             ronda++)
        {
            int cantidadEnviada =
                0;

            long tiempoMicrosegundos =
                0;

            using SendQueue cola =
                new SendQueue(
                    tamanoCola);

            foreach (IPAddress objetivo in objetivos)
            {
                if (!EsDireccionValidaArp(
                        objetivo,
                        direccionIpLocal))
                {
                    continue;
                }

                byte[] tramaArp =
                    CrearSolicitudArpBytes(
                        direccionMacLocal,
                        direccionOrigenArp,
                        objetivo);

                int segundos =
                    (int)(
                        tiempoMicrosegundos /
                        1_000_000L);

                int microsegundos =
                    (int)(
                        tiempoMicrosegundos %
                        1_000_000L);

                if (!cola.Add(
                        tramaArp,
                        segundos,
                        microsegundos))
                {
                    TransmitirColaArp(
                        dispositivoPcap,
                        cola,
                        semaforoEnvioArp,
                        SendQueueTransmitModes.Synchronized);

                    if (!cola.Add(
                            tramaArp,
                            segundos,
                            microsegundos))
                    {
                        throw new InvalidOperationException(
                            "No se pudo agregar la consulta ARP a la cola de transmisión.");
                    }
                }

                tiempoMicrosegundos +=
                    IntervaloSondaArpMicrosegundos;

                cantidadEnviada++;
            }

            if (cola.CurrentLength > 0)
            {
                TransmitirColaArp(
                    dispositivoPcap,
                    cola,
                    semaforoEnvioArp,
                    SendQueueTransmitModes.Synchronized);
            }

            Interlocked.Add(
                ref _sondasArpActuales,
                cantidadEnviada);

            UltimaCantidadSondasArp =
                Volatile.Read(
                    ref _sondasArpActuales);

            Console.WriteLine(
                $"Sondeo ARP optimizado y regulado " +
                $"{ronda}/{cantidadRondas}: " +
                $"{cantidadEnviada} solicitudes.");

            if (ronda < cantidadRondas)
            {
                Thread.Sleep(250);
            }
        }
    }

    private void TransmitirColaArp(
        PcapDevice dispositivoPcap,
        SendQueue cola,
        SemaphoreSlim semaforoEnvioArp,
        SendQueueTransmitModes modo)
    {
        if (cola.CurrentLength == 0)
        {
            return;
        }

        semaforoEnvioArp.Wait();

        try
        {
            int bytesEnviados =
                cola.Transmit(
                    dispositivoPcap,
                    modo);

            if (bytesEnviados <= 0)
            {
                throw new InvalidOperationException(
                    "Npcap no pudo transmitir la cola de solicitudes ARP.");
            }
        }
        finally
        {
            semaforoEnvioArp.Release();
        }
    }

    private byte[] CrearSolicitudArpBytes(
        PhysicalAddress direccionMacLocal,
        IPAddress direccionOrigenArp,
        IPAddress direccionDestino)
    {
        byte[] trama =
            new byte[60];

        byte[] macLocal =
            direccionMacLocal.GetAddressBytes();

        byte[] ipOrigen =
            direccionOrigenArp.AddressFamily ==
                    AddressFamily.InterNetwork
                ? direccionOrigenArp.GetAddressBytes()
                : new byte[] { 0, 0, 0, 0 };

        byte[] ipDestino =
            direccionDestino.GetAddressBytes();

        // Ethernet broadcast.
        for (int indice = 0;
             indice < 6;
             indice++)
        {
            trama[indice] =
                0xFF;

            trama[6 + indice] =
                macLocal[indice];
        }

        trama[12] = 0x08;
        trama[13] = 0x06;

        // ARP: Ethernet / IPv4 / request.
        trama[14] = 0x00;
        trama[15] = 0x01;
        trama[16] = 0x08;
        trama[17] = 0x00;
        trama[18] = 0x06;
        trama[19] = 0x04;
        trama[20] = 0x00;
        trama[21] = 0x01;

        // Sender hardware address.
        Array.Copy(
            macLocal,
            0,
            trama,
            22,
            6);

        // Sender protocol address.
        Array.Copy(
            ipOrigen,
            0,
            trama,
            28,
            4);

        // Target hardware address = unknown (00:00:00:00:00:00).
        // This mantiene el formato estándar de ARP request.
        // El destino Ethernet se mantiene en broadcast para maximizar
        // compatibilidad con switches y dispositivos de gestión.

        // Target protocol address.
        Array.Copy(
            ipDestino,
            0,
            trama,
            38,
            4);

        return trama;
    }

    private long EstimarDuracionArpOptimizadoMs(
        int cantidadRedLocal,
        int cantidadLinkLocal,
        int cantidadRespaldo)
    {
        double velocidadObjetivosPorSegundo =
            5_000.0;

        double redLocal =
            cantidadRedLocal > 0
                ? (cantidadRedLocal * 2.0) /
                  velocidadObjetivosPorSegundo
                : 0.0;

        double linkLocal =
            cantidadLinkLocal > 0
                ? cantidadLinkLocal /
                  velocidadObjetivosPorSegundo
                : 0.0;

        double respaldo =
            cantidadRespaldo > 0
                ? cantidadRespaldo /
                  velocidadObjetivosPorSegundo
                : 0.0;

        // La segunda ronda de Link-Local solo repite candidatos activos,
        // por lo que se agrega un margen de recepción en vez de asumir
        // otro barrido completo.
        double faseArp =
            Math.Max(
                redLocal,
                Math.Max(
                    linkLocal,
                    respaldo));

        return
            6000L +
            (long)(faseArp * 1000.0) +
            800L;
    }

    private long EstimarDuracionArpMs(
        int cantidadRedLocal,
        int cantidadLinkLocal,
        int cantidadRespaldo)
    {
        long redLocal =
            CalcularDuracionSondeoMs(
                cantidadRedLocal,
                2);

        long linkLocal =
            CalcularDuracionSondeoMs(
                cantidadLinkLocal,
                1);

        long respaldo =
            CalcularDuracionSondeoMs(
                cantidadRespaldo,
                1);

        // Las tres búsquedas se ejecutan concurrentemente. La demora total
        // queda limitada aproximadamente por la más larga.
        return
            Math.Max(
                redLocal,
                Math.Max(
                    linkLocal,
                    respaldo))
            + 500;
    }

    private long CalcularDuracionSondeoMs(
        int cantidadObjetivos,
        int cantidadRondas)
    {
        if (cantidadObjetivos <= 0)
        {
            return 0;
        }

        long lotes =
            (cantidadObjetivos +
             TamanoLoteArp -
             1L) /
            TamanoLoteArp;

        return
            lotes *
            PausaLoteArpMs *
            cantidadRondas
            + (cantidadRondas - 1L) * 700L;
    }

    private void AgregarRedComun(
        List<IPAddress> objetivos,
        HashSet<uint> vistos,
        IPAddress direccionIpLocal,
        string direccionRed,
        int prefijo = 24)
    {
        IPAddress red =
            IPAddress.Parse(direccionRed);

        uint baseRed =
            ConvertirIPv4(red);

        uint mascara =
            prefijo == 16
                ? 0xFFFF0000U
                : 0xFFFFFF00U;

        baseRed &= mascara;

        uint broadcast =
            baseRed | ~mascara;

        // Primero .1 y .254 para encontrar rápidamente equipos con
        // direcciones por defecto habituales.
        AgregarObjetivo(
            objetivos,
            vistos,
            ConvertirAIPv4(baseRed + 1U),
            direccionIpLocal);

        AgregarObjetivo(
            objetivos,
            vistos,
            ConvertirAIPv4(broadcast - 1U),
            direccionIpLocal);

        for (uint candidato = baseRed + 1U;
             candidato < broadcast;
             candidato++)
        {
            if (candidato == baseRed + 1U ||
                candidato == broadcast - 1U)
            {
                continue;
            }

            AgregarObjetivo(
                objetivos,
                vistos,
                ConvertirAIPv4(candidato),
                direccionIpLocal);
        }
    }

    private void AgregarObjetivo(
        List<IPAddress> objetivos,
        HashSet<uint> vistos,
        IPAddress direccion,
        IPAddress direccionIpLocal)
    {
        if (!EsDireccionValidaArp(
                direccion,
                direccionIpLocal))
        {
            return;
        }

        uint valor =
            ConvertirIPv4(direccion);

        if (vistos.Add(valor))
        {
            objetivos.Add(direccion);
        }
    }

    private bool EsDireccionValidaArp(
        IPAddress direccion,
        IPAddress direccionIpLocal)
    {
        if (direccion == null ||
            direccion.AddressFamily !=
            AddressFamily.InterNetwork)
        {
            return false;
        }

        if (direccion.Equals(IPAddress.Any) ||
            direccion.Equals(IPAddress.Broadcast) ||
            direccion.Equals(IPAddress.Loopback))
        {
            return false;
        }

        byte primerOcteto =
            direccion.GetAddressBytes()[0];

        if (primerOcteto >= 224 &&
            primerOcteto <= 255)
        {
            return false;
        }

        if (direccionIpLocal != null &&
            direccion.Equals(direccionIpLocal))
        {
            return false;
        }

        return true;
    }

    private void EnviarConsultaArp(
        IInjectionDevice dispositivoInyeccion,
        PhysicalAddress direccionMacLocal,
        PhysicalAddress direccionMacBroadcast,
        PhysicalAddress direccionMacVacia,
        IPAddress direccionDestino,
        IPAddress direccionOrigen)
    {
        ArpPacket solicitudArp =
            new ArpPacket(
                ArpOperation.Request,
                direccionMacVacia,
                direccionDestino,
                direccionMacLocal,
                direccionOrigen);

        EthernetPacket tramaArp =
            new EthernetPacket(
                direccionMacLocal,
                direccionMacBroadcast,
                EthernetType.Arp);

        tramaArp.PayloadPacket =
            solicitudArp;

        dispositivoInyeccion.SendPacket(
            tramaArp);
    }

    private uint ConvertirIPv4(
        IPAddress direccion)
    {
        byte[] bytes =
            direccion.GetAddressBytes();

        return System.Buffers.Binary.BinaryPrimitives
            .ReadUInt32BigEndian(bytes);
    }

    private IPAddress ConvertirAIPv4(
        uint valor)
    {
        byte[] bytes =
            new byte[4];

        System.Buffers.Binary.BinaryPrimitives
            .WriteUInt32BigEndian(
                bytes,
                valor);

        return new IPAddress(bytes);
    }

    private async Task EsperarCondicionAsync(
        Func<bool> condicion,
        TimeSpan tiempoMaximo)
    {
        DateTime limite =
            DateTime.UtcNow.Add(tiempoMaximo);

        while (!condicion() &&
               DateTime.UtcNow < limite)
        {
            await Task.Delay(25);
        }
    }

    private async Task EsperarResultadoAsync(
        DispositivoDetectado resultado,
        TimeSpan tiempoMaximo)
    {
        DateTime limite =
            DateTime.UtcNow.Add(tiempoMaximo);

        while (string.IsNullOrWhiteSpace(resultado.DireccionIP) &&
               DateTime.UtcNow < limite)
        {
            await Task.Delay(25);
        }
    }

    private string NormalizarMac(string direccionMac)
    {
        if (string.IsNullOrWhiteSpace(direccionMac))
        {
            return string.Empty;
        }

        string limpio =
            new string(
                direccionMac
                    .Where(char.IsLetterOrDigit)
                    .ToArray())
            .ToUpperInvariant();

        if (limpio.Length != 12 ||
            limpio.Any(caracter =>
                !(
                    (caracter >= '0' && caracter <= '9') ||
                    (caracter >= 'A' && caracter <= 'F')
                )))
        {
            return string.Empty;
        }

        return
            $"{limpio[0]}{limpio[1]}:" +
            $"{limpio[2]}{limpio[3]}:" +
            $"{limpio[4]}{limpio[5]}:" +
            $"{limpio[6]}{limpio[7]}:" +
            $"{limpio[8]}{limpio[9]}:" +
            $"{limpio[10]}{limpio[11]}";
    }

    private string FormatearMac(PhysicalAddress direccionMac)
    {
        return BitConverter
            .ToString(direccionMac.GetAddressBytes())
            .Replace("-", ":");
    }
}
