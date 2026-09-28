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

            // Si el vecino directamente conectado intercambia tráfico IPv4
            // con la PC, la propia trama ya nos da IP y MAC sin necesitar ARP.
            IPv4Packet ipv4 =
                ethernet.PayloadPacket as IPv4Packet;

            if (ipv4 != null &&
                !EsNuestraIp(ipv4.SourceAddress))
            {
                string macFuenteIpv4 =
                    FormatearMac(
                        ethernet.SourceHardwareAddress);

                bool destinoEsNuestraMac =
                    EsNuestraMac(
                        ethernet.DestinationHardwareAddress);

                bool esVecinoDirecto =
                    vecinoDirectoDetectado &&
                    string.Equals(
                        macFuenteIpv4,
                        macVecinoDirecto,
                        StringComparison.OrdinalIgnoreCase);

                if ((!vecinoDirectoDetectado &&
                     destinoEsNuestraMac) ||
                    esVecinoDirecto)
                {
                    if (!string.IsNullOrWhiteSpace(
                            ipv4.SourceAddress.ToString()) &&
                        !ipv4.SourceAddress.Equals(IPAddress.Any))
                    {
                        resultado.DireccionIP =
                            ipv4.SourceAddress.ToString();

                        resultado.DireccionMac =
                            macFuenteIpv4;

                        RegistrarOrigen("IPv4");

                        return;
                    }
                }
            }

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

            resultado.DireccionIP =
                arp.SenderProtocolAddress.ToString();

            resultado.DireccionMac =
                macFuenteArp;

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

            List<IPAddress> objetivosArp =
                busquedaManual
                    ? new List<IPAddress>
                    {
                        IPAddress.Parse(direccionIPObjetivo)
                    }
                    : ObtenerObjetivosAutomaticos(
                        direccionIpLocal,
                        mascaraRedLocal,
                        puertaEnlace);

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

            // La captura ya está activa; primero escuchamos y después
            // enviamos las sondas para no perder una respuesta rápida.
            Console.WriteLine(
                busquedaManual
                    ? $"Detección dirigida iniciada para {direccionIPObjetivo}."
                    : $"Detección automática iniciada. Sondas ARP: {objetivosArpActivos.Count}.");

            foreach (IPAddress objetivo in objetivosArp)
            {
                if (string.IsNullOrWhiteSpace(
                        resultado.DireccionIP) &&
                    EsDireccionValidaArp(
                        objetivo,
                        direccionIpLocal))
                {
                    EnviarConsultaArp(
                        dispositivoInyeccion,
                        direccionMacLocal,
                        direccionMacBroadcast,
                        direccionMacVacia,
                        objetivo,
                        direccionOrigenArp);

                    if (busquedaManual)
                    {
                        Console.WriteLine(
                            $"Consulta ARP enviada para: {objetivo}");
                    }
                }

                if (!string.IsNullOrWhiteSpace(
                        resultado.DireccionIP))
                {
                    break;
                }
            }

            if (objetivosArpActivos.Count == 0)
            {
                Console.WriteLine(
                    "No se generaron objetivos ARP automáticos. " +
                    "Se continuará únicamente con LLDP, CDP y captura pasiva.");
            }

            await EsperarResultadoAsync(
                resultado,
                TimeSpan.FromSeconds(
                    busquedaManual
                        ? 3
                        : 5));
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
    /// Busca una trama CDP dentro de los bytes crudos del frame
    /// (LLC/SNAP con OUI Cisco 00-00-0C y PID 0x2000).
    /// Extrae Device-ID y la primera dirección IPv4 del Address TLV.
    /// </summary>
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
                    .TrimEnd(' ');
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

    private List<IPAddress> ObtenerObjetivosAutomaticos(
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

        // Primero la puerta de enlace, si existe.
        Agregar(puertaEnlace);

        if (direccionIpLocal != null &&
            mascaraRedLocal != null)
        {
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

            // /31 se utiliza como enlace punto a punto: ambas direcciones
            // son utilizables. Para redes de hasta /16 realizamos un
            // sondeo completo de los hosts de esa red.
            if (cantidadDirecciones == 2UL)
            {
                Agregar(
                    ConvertirAIPv4(red));

                Agregar(
                    ConvertirAIPv4(broadcast));
            }
            else if (cantidadDirecciones <= 65536UL)
            {
                Agregar(
                    ConvertirAIPv4(red + 1U));

                if (broadcast > red + 1U)
                {
                    Agregar(
                        ConvertirAIPv4(broadcast - 1U));
                }

                if (broadcast > red + 1U)
                {
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
                }
            }
        }

        // Candidatos habituales para equipos de administración cuando
        // la PC está en otra red o todavía no tiene IPv4.
        AgregarRedComun(
            objetivos,
            vistos,
            direccionIpLocal,
            "10.0.0.0");

        AgregarRedComun(
            objetivos,
            vistos,
            direccionIpLocal,
            "10.0.1.0");

        AgregarRedComun(
            objetivos,
            vistos,
            direccionIpLocal,
            "192.168.0.0");

        AgregarRedComun(
            objetivos,
            vistos,
            direccionIpLocal,
            "192.168.1.0");

        AgregarRedComun(
            objetivos,
            vistos,
            direccionIpLocal,
            "192.168.100.0");

        AgregarRedComun(
            objetivos,
            vistos,
            direccionIpLocal,
            "172.16.0.0");

        // APIPA/link-local: útil cuando el dispositivo está sin DHCP.
        AgregarRedComun(
            objetivos,
            vistos,
            direccionIpLocal,
            "169.254.0.0",
            16);

        return objetivos;
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
