using ProyectoRed.Web.Models;
using System.Management;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;

namespace ProyectoRed.Web.Services;

public class InterfazRedService
{
    public List<InterfazRed> ObtenerInterfaces()
    {
        NetworkInterface[] interfaces =
            NetworkInterface.GetAllNetworkInterfaces();

        List<InterfazRed> interfacesRed =
            new List<InterfazRed>();

        // En Windows obtenemos una sola vez los identificadores
        // de los adaptadores físicos.
        HashSet<Guid> interfacesFisicasWindows =
            new HashSet<Guid>();

        if (OperatingSystem.IsWindows())
        {
            interfacesFisicasWindows =
                ObtenerInterfacesFisicasWindows();
        }

        foreach (NetworkInterface interfaz in interfaces)
        {
            // Solo trabajamos con interfaces activas de tipo Ethernet.
            if (interfaz.OperationalStatus != OperationalStatus.Up ||
                interfaz.NetworkInterfaceType != NetworkInterfaceType.Ethernet)
            {
                continue;
            }

            // Comprobamos si la interfaz corresponde a un adaptador físico.
            if (!EsInterfazFisica(interfaz, interfacesFisicasWindows))
            {
                continue;
            }

            // Nombre de la interfaz.
            string nombreInterfaz = interfaz.Name;

            // Dirección IPv4 de la interfaz.
            string direccionIp = string.Empty;

            // Obtenemos la dirección MAC de la interfaz.
            PhysicalAddress direccionMac = interfaz.GetPhysicalAddress();

            string macFormateada = BitConverter.ToString(direccionMac.GetAddressBytes()).Replace("-", ":");

            // Obtenemos las propiedades IP de la interfaz.
            IPInterfaceProperties propiedadesIp = interfaz.GetIPProperties();

            string tipo = interfaz.NetworkInterfaceType.ToString();

            // Recorremos las direcciones asociadas a la interfaz.
            foreach (UnicastIPAddressInformation direccion
                     in propiedadesIp.UnicastAddresses)
            {
                // Solo mostramos direcciones IPv4.
                if (direccion.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    direccionIp = direccion.Address.ToString();
                    break;
                }
            }

            interfacesRed.Add(new InterfazRed(
                    nombreInterfaz,
                    direccionIp,
                    macFormateada,
                    tipo
                )
            );
        }

        return interfacesRed;
    }

    private bool EsInterfazFisica(NetworkInterface interfaz,HashSet<Guid> interfacesFisicasWindows)
    {
        // Windows
        if (OperatingSystem.IsWindows())
        {
            if (!Guid.TryParse(interfaz.Id,out Guid identificador))
            {
                return false;
            }

            return interfacesFisicasWindows.Contains(identificador);
        }

        // Linux
        if (OperatingSystem.IsLinux())
        {
            return EsInterfazFisicaLinux(interfaz);
        }

        // No conocemos el sistema operativo.
        return false;
    }

    private bool EsInterfazFisicaLinux(NetworkInterface interfaz)
    {
        string rutaDispositivo = Path.Combine("/sys/class/net",interfaz.Name,"device");

        DirectoryInfo dispositivo = new DirectoryInfo(rutaDispositivo);

        // Las interfaces virtuales normalmente no tienen
        // este enlace hacia un dispositivo de hardware.
        if (!dispositivo.Exists)
        {
            return false;
        }

        try
        {
            FileSystemInfo destino = dispositivo.ResolveLinkTarget(returnFinalTarget: true);

            if (destino == null)
            {
                return false;
            }

            // Si el destino pertenece a /virtual/,
            // estamos ante una interfaz virtual.
            return !destino.FullName.Contains("/virtual/",StringComparison.Ordinal);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private HashSet<Guid> ObtenerInterfacesFisicasWindows()
    {
        HashSet<Guid> resultado =
            new HashSet<Guid>();

        string consulta =
            "SELECT InterfaceGuid " +
            "FROM MSFT_NetAdapter " +
            "WHERE ConnectorPresent = TRUE " +
            "AND HardwareInterface = TRUE " +
            "AND Virtual = FALSE";

        using ManagementObjectSearcher buscador = new ManagementObjectSearcher(@"\\localhost\root\StandardCimv2",consulta);

        foreach (ManagementObject adaptador in buscador.Get())
        {
            string guidTexto = adaptador["InterfaceGuid"]?.ToString();

            if (Guid.TryParse(guidTexto,out Guid guid))
            {
                resultado.Add(guid);
            }
        }

        return resultado;
    }
}