using PacketDotNet;
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

    public string UltimoOrigenDeteccion { get; private set; } = string.Empty;

    public long UltimaDuracionDeteccionMs { get; private set; }

    public long UltimaEstimacionDeteccionMs { get; private set; }

    public string UltimaFaseDeteccion { get; private set; } = string.Empty;

    public int UltimaCantidadSondasArp { get; private set; }

    private const int TamanoLoteArp = 256;

    private const int PausaLoteArpMs = 10;

    public CapturadorPaquetesService(
        HistorialDispositivosService historialDispositivosService)
    {
        _historialDispositivosService = historialDispositivosService;
    }

    public async Task<DispositivoDetectado> CapturarAsync(
        string nombreInterfaz,
        string direccionIPObjetivo = null)
    {
        UltimoOrigenDeteccion = string.Empty;
        UltimaDuracionDeteccionMs = 0;
        UltimaEstimacionDeteccionMs = 0;
        UltimaFaseDeteccion = "Preparando detección";
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

        bool EsNuestraMac(PhysicalAddress direccionMac)
        {
            return direccionMacLocal != null &&
                   direccionMacLocal.GetAddressBytes().Length == 6 &&
                   direccionMac.Equals(direccionMacLocal);
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
                    out string direccionGestionLldp))
            {
                vecinoDirectoDetectado = true;
                macVecinoDirecto = macLldpDirecta;

                resultado.DireccionMac =
                    macLldpDirecta;

                resultado.Nombre =
                    nombreLldpDirecto ?? string.Empty;

                RegistrarOrigen("LLDP");

                // En detección manual la IP introducida por el técnico
                // sigue siendo la dirección objetivo. Si LLDP solo aporta
                // MAC/nombre, continuamos para completar la IP mediante ARP.
                if (!string.IsNullOrWhiteSpace(direccionGestionLldp) &&
                    string.IsNullOrWhiteSpace(direccionIPObjetivo))
                {
                    resultado.DireccionIP =
                        direccionGestionLldp;

                    return;
                }
            }

            // EDP es un protocolo propietario de Extreme Networks
            // encapsulado mediante LLC/SNAP. Cuando está presente,
            // identifica directamente al switch vecino y puede transportar
            // una IP de interfaz VLAN.
            if (IntentarExtraerInformacionEdp(
                    capturaBruta.Data,
                    out string macEdp,
                    out string nombreEdp,
                    out string direccionGestionEdp))
            {
                vecinoDirectoDetectado = true;
                macVecinoDirecto = macEdp;

                resultado.DireccionMac =
                    macEdp;

                resultado.Nombre =
                    nombreEdp ?? string.Empty;

                RegistrarOrigen("EDP");

                if (!string.IsNullOrWhiteSpace(direccionGestionEdp) &&
                    string.IsNullOrWhiteSpace(direccionIPObjetivo))
                {
                    resultado.DireccionIP =
                        direccionGestionEdp;

                    return;
                }
            }

            // STP/RSTP identifica al puente conectado al puerto.
            // Las BPDUs son tramas de enlace local y no se reenvían
            // como tráfico IP por otros switches.
            if (IntentarExtraerInformacionStp(
                    capturaBruta.Data,
                    out string macStp))
            {
                vecinoDirectoDetectado = true;
                macVecinoDirecto = macStp;

                resultado.DireccionMac =
                    macStp;

                RegistrarOrigen("STP");

                return;
            }

            // CDP identifica de la misma forma al vecino Cisco y, cuando
            // el anuncio contiene direcciones, puede aportar la IP.
            IntentarExtraerInformacionCdp(
                capturaBruta.Data,
                out string macCdp,
                out string nombreCdp,
                out string direccionGestionCdp);

            if (!string.IsNullOrWhiteSpace(macCdp))
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

                if (!string.IsNullOrWhiteSpace(direccionGestionCdp) &&
                    string.IsNullOrWhiteSpace(direccionIPObjetivo))
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
                arp.Operation != ArpOperation.Response)
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

            // Si LLDP/CDP identificó un vecino directo pero todavía no
            // tenemos su IP, solo aceptamos ARP proveniente de esa misma MAC.
            if (vecinoDirectoDetectado &&
                !string.Equals(
                    macFuenteArp,
                    macVecinoDirecto,
                    StringComparison.OrdinalIgnoreCase))
            {
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

            lock (sincronizacionArp)
            {
                if (!respuestasArp.TryGetValue(
                        ipRemota,
                        out Dictionary<string, int> macs))
                {
                    macs =
                        new Dictionary<string, int>(
                            StringComparer.OrdinalIgnoreCase);

                    respuestasArp[ipRemota] =
                        macs;
                }

                macs.TryGetValue(
                    macFuenteArp,
                    out int cantidad);

                macs[macFuenteArp] =
                    cantidad + 1;
            }

            RegistrarOrigen("ARP");
        }

        dispositivoSeleccionado.OnPacketArrival +=
            CuandoLlegaPaquete;

        dispositivoSeleccionado.Open(
            DeviceModes.Promiscuous);

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

            bool busquedaManual =
                !string.IsNullOrWhiteSpace(direccionIPObjetivo);

            if (!busquedaManual)
            {
                UltimaFaseDeteccion =
                    "Escuchando LLDP/CDP/STP/EDP";

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
                        "Vecino directo confirmado por LLDP/CDP antes de recurrir a ARP.");
                }
            }

            UltimaFaseDeteccion =
                busquedaManual
                    ? "Preparando ARP dirigido"
                    : "Preparando sondeo ARP";

            List<IPAddress> objetivosArpLocales =
                new List<IPAddress>();

            List<IPAddress> objetivosArpLinkLocal =
                new List<IPAddress>();

            List<IPAddress> objetivosArpRespaldo =
                new List<IPAddress>();

            if (busquedaManual)
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
                        puertaEnlace);

                objetivosArpLinkLocal =
                    ObtenerObjetivosLinkLocal(
                        direccionIpLocal);

                if (vecinoDirectoDetectado)
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

            UltimaCantidadSondasArp =
                objetivosArpActivos.Count;

            UltimaEstimacionDeteccionMs =
                busquedaManual
                    ? 1400
                    : 6000 +
                      EstimarDuracionArpMs(
                          objetivosArpLocales.Count,
                          objetivosArpLinkLocal.Count,
                          objetivosArpRespaldo.Count);

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
            // vecino. Por eso las respuestas se consolidan antes de
            // aceptar una única pareja IP + MAC.
            if (!vecinoDirectoDetectado ||
                string.IsNullOrWhiteSpace(resultado.DireccionIP))
            {
                Console.WriteLine(
                    busquedaManual
                        ? $"Detección dirigida iniciada para {direccionIPObjetivo}."
                        : $"Sin confirmación LLDP/CDP: recurriendo a ARP. Sondas: {objetivosArpActivos.Count}.");

                if (busquedaManual)
                {
                    IPAddress objetivo =
                        IPAddress.Parse(
                            direccionIPObjetivo);

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

                        Console.WriteLine(
                            $"Consulta ARP dirigida {intento}/3 enviada para: {objetivo}");

                        await Task.Delay(100);
                    }
                }
                else
                {
                    UltimaFaseDeteccion =
                        "Sondeo ARP paralelo: red local + 169.254/16";

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
                        SondearArpAsync(
                            dispositivoInyeccion,
                            objetivosArpLinkLocal,
                            direccionIpLocal,
                            direccionMacLocal,
                            direccionMacBroadcast,
                            direccionMacVacia,
                            direccionOrigenArp,
                            1,
                            semaforoEnvioArp);

                    Task tareaRespaldo =
                        SondearArpAsync(
                            dispositivoInyeccion,
                            objetivosArpRespaldo,
                            direccionIpLocal,
                            direccionMacLocal,
                            direccionMacBroadcast,
                            direccionMacVacia,
                            direccionOrigenArp,
                            1,
                            semaforoEnvioArp);

                    await Task.WhenAll(
                        tareaRedLocal,
                        tareaLinkLocal,
                        tareaRespaldo);

                    semaforoEnvioArp.Dispose();
                }
            }
            else
            {
                Console.WriteLine(
                    "IP resuelta por LLDP/CDP; se omite el escaneo ARP.");
            }

            if (objetivosArpActivos.Count == 0)
            {
                Console.WriteLine(
                    "No se generaron objetivos ARP automáticos. " +
                    "Se continuará únicamente con LLDP, CDP y captura pasiva.");
            }

            UltimaFaseDeteccion =
                "Consolidando respuestas";

            if (!busquedaManual)
            {
                await Task.Delay(500);

                if (string.IsNullOrWhiteSpace(
                        resultado.DireccionIP))
                {
                    ResolverResultadoArpAutomatico(
                        resultado,
                        respuestasArp,
                        vecinoDirectoDetectado,
                        macVecinoDirecto);
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

        macOrigen =
            FormatearMac(
                new PhysicalAddress(
                    datos.Skip(6).Take(6).ToArray()));

        int inicioEdp =
            inicioLlc + 8;

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

                    if (!ip.Equals(IPAddress.Any) &&
                        !ip.Equals(
                            IPAddress.Broadcast))
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

    private void ResolverResultadoArpAutomatico(
        DispositivoDetectado resultado,
        Dictionary<uint, Dictionary<string, int>> respuestasArp,
        bool vecinoDirectoDetectado,
        string macVecinoDirecto)
    {
        List<(uint ip, string mac, int cantidad)> candidatos =
            new List<(uint ip, string mac, int cantidad)>();

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

                candidatos.Add(
                    (respuesta.Key,
                     mac.Key,
                     mac.Value));
            }
        }

        if (candidatos.Count == 0)
        {
            return;
        }

        int mayorCantidad =
            candidatos.Max(
                candidato => candidato.cantidad);

        List<(uint ip, string mac, int cantidad)> mejores =
            candidatos
                .Where(candidato =>
                    candidato.cantidad == mayorCantidad)
                .ToList();

        // Requerimos dos respuestas del mismo candidato para reducir
        // falsos positivos y hacemos que varios intentos produzcan el
        // mismo resultado en lugar de depender del primero que respondió.
        if (mayorCantidad < 2 ||
            mejores.Count != 1)
        {
            return;
        }

        resultado.DireccionIP =
            ConvertirAIPv4(
                mejores[0].ip)
            .ToString();

        resultado.DireccionMac =
            mejores[0].mac;
    }

    private List<IPAddress> ObtenerObjetivosRedLocal(
        IPAddress direccionIpLocal,
        IPAddress mascaraRedLocal,
        IPAddress puertaEnlace)
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
                }
                finally
                {
                    semaforoEnvioArp.Release();
                }

                cantidadEnviada++;

                if (cantidadEnviada % TamanoLoteArp == 0)
                {
                    await Task.Delay(
                        PausaLoteArpMs);
                }
            }

            Console.WriteLine(
                $"Sondeo ARP {ronda}/{cantidadRondas}: " +
                $"{cantidadEnviada} solicitudes.");

            if (ronda < cantidadRondas)
            {
                await Task.Delay(700);
            }
        }
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

    private string FormatearMac(PhysicalAddress direccionMac)
    {
        return BitConverter
            .ToString(direccionMac.GetAddressBytes())
            .Replace("-", ":");
    }
}
