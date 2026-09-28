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
                    $"http://{direccionIP}",
                PuedeAbrirInterfaz =
                    mismaRed
            };

        if (mismaRed)
        {
            resultado.Mensaje =
                $"La PC y el dispositivo están en la misma red IPv4. " +
                $"Se puede abrir la interfaz en {resultado.UrlInterfaz}.";
        }
        else if (usaDhcp)
        {
            resultado.Mensaje =
                "La PC y el dispositivo están en redes IPv4 diferentes y " +
                "la interfaz seleccionada está configurada por DHCP. " +
                "Compruebe que exista un servidor DHCP que entregue una " +
                "dirección de la misma red que el dispositivo. Si el dispositivo " +
                "utiliza una IP fija, configure temporalmente la interfaz de la PC " +
                "de forma manual.";
        }
        else
        {
            resultado.Mensaje =
                "La PC y el dispositivo están en redes IPv4 diferentes. " +
                "La interfaz de la PC está configurada manualmente. " +
                "Configure temporalmente una dirección de la misma red del " +
                "dispositivo para poder acceder a su interfaz.";
        }

        resultado.ConfiguracionManual =
            CrearConfiguracionManual(
                direccionIP,
                mascaraRed,
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
        IPAddress mascaraRed,
        IPAddress direccionIPLocal)
    {
        uint dispositivo =
            ConvertirIPv4(direccionIPDispositivo);

        uint local =
            ConvertirIPv4(direccionIPLocal);

        uint mascara =
            ConvertirIPv4(mascaraRed);

        uint red =
            dispositivo & mascara;

        uint broadcast =
            red | ~mascara;

        uint[] candidatos =
        {
            red + 2,
            red + 1,
            red + 3
        };

        foreach (uint candidato in candidatos)
        {
            if (candidato <= red ||
                candidato >= broadcast ||
                candidato == dispositivo ||
                candidato == local)
            {
                continue;
            }

            return new ConfiguracionManualRed
            {
                DireccionIP =
                    ConvertirAIPv4(candidato).ToString(),
                MascaraRed =
                    mascaraRed.ToString(),
                PuertaEnlace = string.Empty
            };
        }

        return new ConfiguracionManualRed
        {
            MascaraRed =
                mascaraRed.ToString()
        };
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
