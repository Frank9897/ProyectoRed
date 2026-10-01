using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using ProyectoRed.Web.Models;

namespace ProyectoRed.Web.Services;

public class AccesoDispositivoService
{
    public EstadoAccesoDispositivo Evaluar(
        string nombreInterfaz,
        string direccionIPDispositivo)
    {
        if (!IPAddress.TryParse(
                direccionIPDispositivo,
                out IPAddress direccionIP) ||
            direccionIP.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new InvalidOperationException(
                "La dirección IP del dispositivo no es una IPv4 válida.");
        }

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
                "La detección del dispositivo puede realizarse sin IPv4, " +
                "pero para abrir su interfaz primero debe configurar una IPv4 en la PC.");
        }

        IPAddress direccionIPLocal =
            direccionLocal.Address;

        IPAddress mascaraRed =
            direccionLocal.IPv4Mask;

        bool usaDhcp = false;

        if (OperatingSystem.IsWindows())
        {
            IPv4InterfaceProperties propiedadesIpv4 =
                interfazRed.GetIPProperties().GetIPv4Properties();

            usaDhcp =
                propiedadesIpv4 != null &&
                propiedadesIpv4.IsDhcpEnabled;
        }

        bool mismaRed =
            PerteneceMismaRed(
                direccionIPLocal,
                direccionIP,
                mascaraRed);

        string urlInterfaz =
            await DetectarUrlInterfazAsync(
                direccionIP);

        bool puedeAbrirInterfaz =
            !string.IsNullOrWhiteSpace(
                urlInterfaz);

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
                    puedeAbrirInterfaz
            };

        if (puedeAbrirInterfaz)
        {
            resultado.Mensaje =
                $"Se detectó un servicio web en {urlInterfaz}.";
        }
        else if (mismaRed)
        {
            resultado.Mensaje =
                "La PC y el dispositivo parecen pertenecer a la misma " +
                "subred según la configuración actual, pero no se detectó " +
                "un servicio web en los puertos habituales 80, 443, 8080 o 8443.";
        }
        else if (usaDhcp)
        {
            resultado.Mensaje =
                "La PC y el dispositivo no parecen estar en la misma subred " +
                "con la configuración actual. El dispositivo puede utilizar " +
                "una IP fija. Configure temporalmente la interfaz Ethernet con " +
                "la IP y máscara sugeridas y vuelva a probar el acceso.";
        }
        else
        {
            resultado.Mensaje =
                "La PC y el dispositivo no parecen estar en la misma subred " +
                "con la configuración actual. Configure temporalmente la " +
                "interfaz Ethernet con la IP y máscara sugeridas y vuelva a " +
                "probar el acceso.";
        }

        resultado.ConfiguracionManual =
            CrearConfiguracionManual(
                direccionIP,
                direccionIPLocal);

        return resultado;
    }

    private bool PerteneceMismaRed(
        IPAddress direccionIPLocal,
        IPAddress direccionIPDispositivo,
        IPAddress mascaraRed)
    {
        uint ipLocal =
            ConvertirIPv4(direccionIPLocal);

        uint ipDispositivo =
            ConvertirIPv4(direccionIPDispositivo);

        uint mascara =
            ConvertirIPv4(mascaraRed);

        return (ipLocal & mascara) ==
               (ipDispositivo & mascara);
    }

    private ConfiguracionManualRed CrearConfiguracionManual(
        IPAddress direccionIPDispositivo,
        IPAddress direccionIPLocal)
    {
        byte[] bytesDispositivo =
            direccionIPDispositivo.GetAddressBytes();

        int host =
            bytesDispositivo[3];

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

        byte[] bytesIpSugerida =
        {
            bytesDispositivo[0],
            bytesDispositivo[1],
            bytesDispositivo[2],
            (byte)hostSugerido
        };

        IPAddress ipSugerida =
            new IPAddress(bytesIpSugerida);

        if (ipSugerida.Equals(direccionIPLocal))
        {
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
            MascaraRed =
                "255.255.255.0",
            PuertaEnlace =
                string.Empty
        };
    }

    private async Task<string> DetectarUrlInterfazAsync(
        IPAddress direccionIP)
    {
        (int Puerto, string Esquema)[] puertos =
        {
            (443, "https"),
            (80, "http"),
            (8443, "https"),
            (8080, "http")
        };

        foreach ((int Puerto, string Esquema) puerto in puertos)
        {
            if (await PuertoWebAbiertoAsync(
                    direccionIP,
                    puerto.Puerto))
            {
                return
                    $"{puerto.Esquema}://{direccionIP}" +
                    (puerto.Puerto is 80 or 443
                        ? string.Empty
                        : $":{puerto.Puerto}");
            }
        }

        return string.Empty;
    }

    private async Task<bool> PuertoWebAbiertoAsync(
        IPAddress direccionIP,
        int puerto)
    {
        using TcpClient cliente =
            new TcpClient();

        try
        {
            await cliente.ConnectAsync(
                    direccionIP,
                    puerto)
                .WaitAsync(
                    TimeSpan.FromMilliseconds(600));

            return cliente.Connected;
        }
        catch
        {
            return false;
        }
    }

    private uint ConvertirIPv4(IPAddress direccion)
    {
        byte[] bytes =
            direccion.GetAddressBytes();

        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    private IPAddress ConvertirAIPv4(uint valor)
    {
        byte[] bytes = new byte[4];

        BinaryPrimitives.WriteUInt32BigEndian(
            bytes,
            valor);

        return new IPAddress(bytes);
    }
}
