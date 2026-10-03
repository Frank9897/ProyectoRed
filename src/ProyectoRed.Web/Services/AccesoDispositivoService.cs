using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using ProyectoRed.Web.Models;

namespace ProyectoRed.Web.Services;

public class AccesoDispositivoService
{
    /// <summary>
    /// Métodos de administración que se comprueban exclusivamente contra
    /// la IP ya detectada del dispositivo.
    ///
    /// Cada entrada contiene:
    /// Nombre: etiqueta que verá el técnico.
    /// Protocolo: tipo de prueba que realizará el servicio.
    /// Puerto: puerto TCP que se comprobará.
    ///
    /// Cambiar esta lista modifica directamente qué servicios intenta
    /// descubrir ProyectoRed y cuánto tiempo puede durar esta comprobación.
    /// </summary>
    private static readonly (
        string Nombre,
        string Protocolo,
        int Puerto)[] MetodosGestion =
    {
        ("HTTPS", "HTTPS", 443),
        ("HTTP", "HTTP", 80),
        ("HTTPS", "HTTPS", 8443),
        ("HTTP", "HTTP", 8080),
        ("SSH", "SSH", 22),
        ("Telnet", "TELNET", 23)
    };

    /// <summary>
    /// Tiempo máximo permitido para cada conexión/protocolo.
    /// Aumentarlo mejora la tolerancia a equipos lentos, pero aumenta el
    /// tiempo total cuando un puerto está cerrado o filtrado.
    /// </summary>
    private static readonly TimeSpan TiempoEsperaServicio =
        TimeSpan.FromMilliseconds(1200);

    /// <summary>
    /// Evalúa si la PC puede acceder al dispositivo y detecta los métodos
    /// de administración disponibles en la IP ya descubierta.
    /// </summary>
    public async Task<EstadoAccesoDispositivo> EvaluarAsync(
        string nombreInterfaz,
        string direccionIPDispositivo)
    {
        // direccionIP es la IPv4 exacta que ya obtuvo ProyectoRed.
        // Cambiarla modifica el equipo contra el que se realizarán
        // todas las comprobaciones de acceso.
        if (!IPAddress.TryParse(
                direccionIPDispositivo,
                out IPAddress direccionIP) ||
            direccionIP.AddressFamily !=
                AddressFamily.InterNetwork)
        {
            throw new InvalidOperationException(
                "La dirección IP del dispositivo no es una IPv4 válida.");
        }

        // interfazRed es la interfaz Ethernet seleccionada por el técnico.
        // Cambiar su selección modifica la IP/máscara usadas para decidir
        // si el dispositivo es accesible desde esa interfaz.
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

        // direccionLocal contiene la IPv4 local y su máscara asociada.
        // Cambiar esta referencia altera la red desde la cual se evalúa
        // el acceso al dispositivo.
        UnicastIPAddressInformation direccionLocal =
            interfazRed.GetIPProperties()
                .UnicastAddresses
                .FirstOrDefault(direccion =>
                    direccion.Address.AddressFamily ==
                    AddressFamily.InterNetwork);

        if (direccionLocal == null)
        {
            throw new InvalidOperationException(
                $"La PC no tiene una dirección IPv4 configurada en la interfaz '{nombreInterfaz}'. " +
                "La detección puede realizarse sin IPv4, pero el acceso por IP " +
                "requiere configurar temporalmente una IPv4 en la PC.");
        }

        // direccionIPLocal es la IPv4 actual de la PC.
        // Cambiarla modifica la dirección que se considera como origen
        // lógico para la comparación de subred.
        IPAddress direccionIPLocal =
            direccionLocal.Address;

        // mascaraRed es la máscara real de la PC.
        // Cambiarla modifica el resultado de la comparación entre redes.
        IPAddress mascaraRed =
            direccionLocal.IPv4Mask;

        // usaDhcp solo informa si Windows tiene DHCP habilitado.
        // Cambiarlo únicamente cambia la explicación presentada al técnico.
        bool usaDhcp = false;

        if (OperatingSystem.IsWindows())
        {
            // propiedadesIpv4 contiene la configuración IPv4 específica
            // de Windows para esta interfaz.
            // Cambiarla no modifica la red; solo cambia qué dato consulta
            // el servicio para saber si DHCP está activo.
            IPv4InterfaceProperties propiedadesIpv4 =
                interfazRed.GetIPProperties()
                    .GetIPv4Properties();

            usaDhcp =
                propiedadesIpv4 != null &&
                propiedadesIpv4.IsDhcpEnabled;
        }

        // mismaRed determina si la IP del dispositivo pertenece a la misma
        // subred que la PC según la máscara local.
        // Cambiar la lógica de esta comparación altera si se intentan
        // conexiones directas contra los servicios del dispositivo.
        bool mismaRed =
            PerteneceMismaRed(
                direccionIPLocal,
                direccionIP,
                mascaraRed);

        // metodosAcceso contiene exclusivamente los servicios que respondieron
        // en la IP del dispositivo. Modificar su construcción cambia lo que
        // la interfaz muestra como disponible.
        List<MetodoAccesoDispositivo> metodosAcceso =
            mismaRed
                ? await DetectarMetodosAccesoAsync(
                    direccionIP)
                : new List<MetodoAccesoDispositivo>();

        // urlInterfaz es la primera URL web válida encontrada, priorizando
        // HTTPS y luego HTTP. Cambiar esta selección modifica qué URL utiliza
        // el botón "Abrir interfaz del dispositivo".
        string urlInterfaz =
            metodosAcceso
                .Where(metodo =>
                    metodo.Protocolo.Equals(
                        "HTTPS",
                        StringComparison.OrdinalIgnoreCase) ||
                    metodo.Protocolo.Equals(
                        "HTTP",
                        StringComparison.OrdinalIgnoreCase))
                .Select(metodo => metodo.Url)
                .FirstOrDefault(url =>
                    !string.IsNullOrWhiteSpace(url))
                ?? string.Empty;

        // puedeAbrirInterfaz indica si existe al menos una interfaz web
        // comprobada y válida. Modificarlo cambia el estado del botón web.
        bool puedeAbrirInterfaz =
            !string.IsNullOrWhiteSpace(urlInterfaz);

        // resultado reúne toda la información que consume HomeController
        // y la vista. Cambiar una propiedad modifica directamente la respuesta
        // JSON que recibe el navegador.
        EstadoAccesoDispositivo resultado =
            new EstadoAccesoDispositivo
            {
                MismaRed = mismaRed,
                UsaDhcp = usaDhcp,
                DireccionIPLocal =
                    direccionIPLocal.ToString(),
                MascaraRedLocal =
                    mascaraRed.ToString(),
                UrlInterfaz =
                    urlInterfaz,
                PuedeAbrirInterfaz =
                    puedeAbrirInterfaz,
                MetodosAcceso =
                    metodosAcceso
            };

        if (puedeAbrirInterfaz)
        {
            // resultado.Mensaje explica cuál fue la interfaz web detectada.
            resultado.Mensaje =
                $"Se detectó acceso web mediante {urlInterfaz}.";
        }
        else if (metodosAcceso.Count > 0)
        {
            // nombresMetodos resume los protocolos no web encontrados,
            // por ejemplo SSH o Telnet.
            string nombresMetodos =
                string.Join(
                    ", ",
                    metodosAcceso.Select(
                        metodo =>
                            $"{metodo.Nombre} ({metodo.Puerto})"));

            resultado.Mensaje =
                $"Se detectaron métodos de acceso: {nombresMetodos}.";
        }
        else if (mismaRed)
        {
            resultado.Mensaje =
                "La PC y el dispositivo están en la misma subred, " +
                "pero no se detectó HTTP, HTTPS, SSH ni Telnet en los " +
                "puertos comprobados.";
        }
        else if (usaDhcp)
        {
            resultado.Mensaje =
                "La PC y el dispositivo no parecen estar en la misma subred " +
                "con la configuración actual. Configure temporalmente la " +
                "interfaz Ethernet con la IP y máscara sugeridas y vuelva a " +
                "probar el acceso.";
        }
        else
        {
            resultado.Mensaje =
                "La PC y el dispositivo no parecen estar en la misma subred " +
                "con la configuración actual. Configure temporalmente la " +
                "interfaz Ethernet con la IP y máscara sugeridas y vuelva a " +
                "probar el acceso.";
        }

        // ConfiguracionManual sigue siendo solo una guía; ProyectoRed no
        // modifica automáticamente la configuración de Windows.
        resultado.ConfiguracionManual =
            CrearConfiguracionManual(
                direccionIP,
                direccionIPLocal);

        return resultado;
    }

    /// <summary>
    /// Ejecuta en paralelo las comprobaciones de acceso contra la única IP
    /// del dispositivo. No recorre ninguna otra dirección de la red.
    /// </summary>
    private async Task<List<MetodoAccesoDispositivo>> DetectarMetodosAccesoAsync(
        IPAddress direccionIP)
    {
        // tareas representa una comprobación independiente por cada método.
        // Cambiar la cantidad de tareas modifica la cantidad de servicios
        // que se prueban simultáneamente.
        Task<MetodoAccesoDispositivo>[] tareas =
            MetodosGestion
                .Select(definicion =>
                    ProbarMetodoAsync(
                        direccionIP,
                        definicion.Nombre,
                        definicion.Protocolo,
                        definicion.Puerto))
                .ToArray();

        // resultados espera todas las comprobaciones y reúne sus respuestas.
        // Cambiar esta espera por ejecución secuencial aumentaría el tiempo
        // cuando existen varios puertos cerrados.
        MetodoAccesoDispositivo[] resultados =
            await Task.WhenAll(tareas);

        return resultados
            .Where(resultado =>
                resultado.Disponible)
            .ToList();
    }

    /// <summary>
    /// Comprueba un único método de administración.
    /// </summary>
    private async Task<MetodoAccesoDispositivo> ProbarMetodoAsync(
        IPAddress direccionIP,
        string nombre,
        string protocolo,
        int puerto)
    {
        // resultado representa únicamente este servicio y se devuelve a
        // DetectarMetodosAccesoAsync. Cambiarlo modifica el resultado de
        // la prueba de ese puerto.
        MetodoAccesoDispositivo resultado =
            new MetodoAccesoDispositivo
            {
                Nombre = nombre,
                Protocolo = protocolo,
                Puerto = puerto
            };

        // disponible indica si el protocolo respondió de forma compatible.
        // Cambiarlo manualmente falsearía la detección, por eso se calcula
        // exclusivamente con la prueba de red.
        bool disponible;

        switch (protocolo)
        {
            case "HTTP":
                disponible =
                    await ProbarWebAsync(
                        direccionIP,
                        puerto,
                        false);
                break;

            case "HTTPS":
                disponible =
                    await ProbarWebAsync(
                        direccionIP,
                        puerto,
                        true);
                break;

            case "SSH":
                disponible =
                    await ProbarSshAsync(
                        direccionIP,
                        puerto);
                break;

            case "TELNET":
                // Telnet no tiene un banner obligatorio universal que
                // podamos validar de forma tan consistente como SSH.
                // Por eso la evidencia utilizada es una conexión TCP
                // satisfactoria al puerto 23.
                disponible =
                    await ProbarPuertoTcpAsync(
                        direccionIP,
                        puerto);
                break;

            default:
                disponible = false;
                break;
        }

        resultado.Disponible =
            disponible;

        if (!disponible)
        {
            return resultado;
        }

        if (protocolo.Equals(
                "HTTP",
                StringComparison.OrdinalIgnoreCase) ||
            protocolo.Equals(
                "HTTPS",
                StringComparison.OrdinalIgnoreCase))
        {
            // esquema define el protocolo que se colocará en la URL.
            // Cambiarlo modificaría la URL de apertura del navegador.
            string esquema =
                protocolo.ToLowerInvariant();

            resultado.Url =
                $"{esquema}://{direccionIP}" +
                (puerto is 80 or 443
                    ? string.Empty
                    : $":{puerto}");
        }
        else if (protocolo.Equals(
                     "SSH",
                     StringComparison.OrdinalIgnoreCase))
        {
            resultado.Comando =
                $"ssh {direccionIP}";
        }
        else if (protocolo.Equals(
                     "TELNET",
                     StringComparison.OrdinalIgnoreCase))
        {
            resultado.Comando =
                $"telnet {direccionIP} {puerto}";
        }

        return resultado;
    }

    /// <summary>
    /// Comprueba HTTP o HTTPS mediante una conexión directa al dispositivo.
    /// No utiliza proxy ni Internet.
    /// </summary>
    private async Task<bool> ProbarWebAsync(
        IPAddress direccionIP,
        int puerto,
        bool usarTls)
    {
        // clienteTCP es la conexión directa a la IPv4 descubierta.
        // Cambiarlo por otro tipo de conexión podría introducir dependencias
        // de proxy o de la configuración del navegador.
        using TcpClient clienteTCP =
            new TcpClient();

        // canalTCP es el flujo de bytes de la conexión.
        // Cambiarlo modifica la forma en que se envía la solicitud HTTP.
        NetworkStream canalTCP;

        // sslStream se utiliza solamente para HTTPS.
        // Cambiar la validación del certificado alteraría la capacidad de
        // diagnosticar equipos con certificados autofirmados.
        SslStream sslStream = null;

        try
        {
            await clienteTCP.ConnectAsync(
                    direccionIP,
                    puerto)
                .WaitAsync(
                    TiempoEsperaServicio);

            canalTCP =
                clienteTCP.GetStream();

            // canal es el flujo que utilizará la prueba HTTP/HTTPS.
            // En HTTPS se reemplaza por sslStream para envolver el mismo
            // transporte TCP con TLS.
            Stream canal =
                canalTCP;

            if (usarTls)
            {
                sslStream =
                    new SslStream(
                        canalTCP,
                        leaveInnerStreamOpen: false,
                        userCertificateValidationCallback:
                            static (
                                sender,
                                certificate,
                                chain,
                                errors) =>
                            {
                                // sender es el objeto que dispara la validación.
                                // certificate es el certificado presentado.
                                // chain es la cadena de certificación.
                                // errors contiene los errores de validación.
                                // Ninguno cambia la decisión de servicio en
                                // esta prueba diagnóstica: solo interesa saber
                                // si existe TLS en el dispositivo.
                                return true;
                            });

                await sslStream.AuthenticateAsClientAsync(
                        new SslClientAuthenticationOptions
                        {
                            TargetHost =
                                direccionIP.ToString(),
                            EnabledSslProtocols =
                                SslProtocols.None
                        })
                    .WaitAsync(
                        TiempoEsperaServicio);

                canal =
                    sslStream;
            }

            // solicitud es una petición GET al recurso raíz. Se usa GET
            // porque algunos paneles embebidos no implementan HEAD.
            // Solo leemos los primeros bytes y cerramos la conexión;
            // no descargamos la página completa.
            byte[] solicitud =
                Encoding.ASCII.GetBytes(
                    "GET / HTTP/1.0\r\n" +
                    $"Host: {direccionIP}\r\n" +
                    "Accept: */*\r\n" +
                    "Connection: close\r\n\r\n");

            await canal.WriteAsync(
                    solicitud,
                    0,
                    solicitud.Length)
                .WaitAsync(
                    TiempoEsperaServicio);

            // bufferRespuesta almacena solamente una pequeña parte de la
            // cabecera HTTP; no necesitamos descargar la página completa.
            byte[] bufferRespuesta =
                new byte[256];

            // bytesLeidos indica cuántos bytes devolvió el dispositivo.
            // Cambiar el tamaño del buffer cambia cuánta cabecera podemos
            // inspeccionar de una sola vez.
            int bytesLeidos =
                await canal.ReadAsync(
                        bufferRespuesta,
                        0,
                        bufferRespuesta.Length)
                    .WaitAsync(
                        TiempoEsperaServicio);

            if (bytesLeidos <= 0)
            {
                return false;
            }

            // cabeceraRespuesta contiene la respuesta inicial en ASCII.
            // Cambiar esta conversión podría afectar el reconocimiento
            // del prefijo "HTTP/".
            string cabeceraRespuesta =
                Encoding.ASCII.GetString(
                    bufferRespuesta,
                    0,
                    bytesLeidos);

            return cabeceraRespuesta.StartsWith(
                "HTTP/",
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
        finally
        {
            // sslStream puede ser nulo cuando se probó HTTP.
            sslStream?.Dispose();
        }
    }

    /// <summary>
    /// Comprueba SSH validando el banner inicial del servidor.
    /// </summary>
    private async Task<bool> ProbarSshAsync(
        IPAddress direccionIP,
        int puerto)
    {
        // clienteSSH es la conexión al servidor SSH.
        // Cambiar el tipo de conexión modificaría la prueba de banner.
        using TcpClient clienteSSH =
            new TcpClient();

        try
        {
            await clienteSSH.ConnectAsync(
                    direccionIP,
                    puerto)
                .WaitAsync(
                    TiempoEsperaServicio);

            // flujoSSH contiene el banner que el servidor SSH debe presentar
            // al iniciar la conexión.
            NetworkStream flujoSSH =
                clienteSSH.GetStream();

            // bufferBanner evita almacenar más información de la necesaria.
            byte[] bufferBanner =
                new byte[256];

            // bytesLeidos indica si el dispositivo realmente entregó un banner.
            int bytesLeidos =
                await flujoSSH.ReadAsync(
                        bufferBanner,
                        0,
                        bufferBanner.Length)
                    .WaitAsync(
                        TiempoEsperaServicio);

            if (bytesLeidos <= 0)
            {
                return false;
            }

            // bannerSSH contiene el texto inicial del protocolo.
            string bannerSSH =
                Encoding.ASCII.GetString(
                    bufferBanner,
                    0,
                    bytesLeidos);

            return bannerSSH.StartsWith(
                "SSH-",
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Comprueba únicamente si se puede establecer una conexión TCP.
    /// Se utiliza para Telnet, cuyo reconocimiento universal no es tan
    /// sencillo como el banner de SSH.
    /// </summary>
    private async Task<bool> ProbarPuertoTcpAsync(
        IPAddress direccionIP,
        int puerto)
    {
        // clienteTCP es la conexión directa al puerto que se quiere probar.
        // Cambiar puerto modifica el servicio TCP comprobado.
        using TcpClient clienteTCP =
            new TcpClient();

        try
        {
            await clienteTCP.ConnectAsync(
                    direccionIP,
                    puerto)
                .WaitAsync(
                    TiempoEsperaServicio);

            return clienteTCP.Connected;
        }
        catch
        {
            return false;
        }
    }

    private bool PerteneceMismaRed(
        IPAddress direccionIPLocal,
        IPAddress direccionIPDispositivo,
        IPAddress mascaraRed)
    {
        // ipLocal es la IPv4 de la PC convertida a entero para la operación AND.
        // Cambiarla cambia la red de referencia.
        uint ipLocal =
            ConvertirIPv4(direccionIPLocal);

        // ipDispositivo es la IPv4 detectada convertida al mismo formato.
        // Cambiarla modifica la red calculada para el dispositivo.
        uint ipDispositivo =
            ConvertirIPv4(direccionIPDispositivo);

        // mascara es la máscara IPv4 convertida a entero.
        // Cambiarla modifica qué bits se consideran parte de la red.
        uint mascara =
            ConvertirIPv4(mascaraRed);

        return (ipLocal & mascara) ==
               (ipDispositivo & mascara);
    }

    private ConfiguracionManualRed CrearConfiguracionManual(
        IPAddress direccionIPDispositivo,
        IPAddress direccionIPLocal)
    {
        // bytesDispositivo contiene los cuatro octetos de la IP detectada.
        // Cambiar la IP de entrada cambia directamente la IP temporal sugerida.
        byte[] bytesDispositivo =
            direccionIPDispositivo.GetAddressBytes();

        // host representa el último octeto de la IP del dispositivo.
        // Cambiar esta variable cambia qué host adyacente se propone.
        int host =
            bytesDispositivo[3];

        // hostSugerido será el último octeto de la IP temporal.
        // Cambiar el cálculo puede generar una IP usada por otro dispositivo.
        int hostSugerido;

        if (host >= 1 &&
            host <= 253)
        {
            hostSugerido =
                host + 1;
        }
        else
        {
            hostSugerido =
                host - 1;

            if (hostSugerido <= 0)
            {
                hostSugerido = 2;
            }
        }

        // bytesIpSugerida contiene la IP temporal que se mostrará al técnico.
        // Cambiar sus octetos modifica la dirección propuesta para la PC.
        byte[] bytesIpSugerida =
        {
            bytesDispositivo[0],
            bytesDispositivo[1],
            bytesDispositivo[2],
            (byte)hostSugerido
        };

        // ipSugerida es la IPv4 temporal resultante.
        // Cambiarla modifica directamente la configuración mostrada.
        IPAddress ipSugerida =
            new IPAddress(bytesIpSugerida);

        if (ipSugerida.Equals(direccionIPLocal))
        {
            // Este ajuste evita sugerir la misma IP que ya posee la PC.
            // Cambiarlo puede volver a producir un conflicto de dirección.
            hostSugerido +=
                hostSugerido < 253
                    ? 1
                    : -2;

            ipSugerida =
                new IPAddress(
                    new byte[]
                    {
                        bytesDispositivo[0],
                        bytesDispositivo[1],
                        bytesDispositivo[2],
                        (byte)hostSugerido
                    });
        }

        return new ConfiguracionManualRed
        {
            DireccionIP =
                ipSugerida.ToString(),
            // La máscara /24 se mantiene como primera prueba temporal.
            // Cambiarla modifica la red que tendrá la PC durante la prueba.
            MascaraRed =
                "255.255.255.0",
            // No se necesita gateway para una conexión local directa.
            // Cambiarlo podría hacer que Windows intente enrutar el tráfico.
            PuertaEnlace =
                string.Empty
        };
    }

    private uint ConvertirIPv4(
        IPAddress direccion)
    {
        // bytes contiene los cuatro octetos IPv4.
        // Cambiar el orden de lectura alteraría todas las operaciones de red.
        byte[] bytes =
            direccion.GetAddressBytes();

        return BinaryPrimitives.ReadUInt32BigEndian(
            bytes);
    }

    private IPAddress ConvertirAIPv4(
        uint valor)
    {
        // bytes reconstruye los cuatro octetos de una IPv4.
        // Cambiar su tamaño o el orden de escritura produciría direcciones
        // inválidas o invertidas.
        byte[] bytes =
            new byte[4];

        BinaryPrimitives.WriteUInt32BigEndian(
            bytes,
            valor);

        return new IPAddress(bytes);
    }
}
