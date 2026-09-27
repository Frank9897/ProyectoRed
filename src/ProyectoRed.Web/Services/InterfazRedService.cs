using ProyectoRed.Web.Models;
using System.Net.NetworkInformation;
using System.Net.Sockets;
namespace ProyectoRed.Web.Services;
public class InterfazRedService
{
    public List<InterfazRed> ObtenerInterfaces()
    {
        NetworkInterface[] interfaces =
            NetworkInterface.GetAllNetworkInterfaces();
        
        List<InterfazRed> interfacesRed = new List<InterfazRed>();

        foreach (NetworkInterface interfaz in interfaces)
        {
            // Solo trabajamos con interfaces que están activas.
            if (interfaz.OperationalStatus != OperationalStatus.Up || interfaz.NetworkInterfaceType != NetworkInterfaceType.Ethernet)
            {
                continue;
            }

            // Nombre de la interfaz, por ejemplo: Ethernet.
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
                }
            }
            
            interfacesRed.Add(new InterfazRed(nombreInterfaz, direccionIp, macFormateada, tipo));
        }
        return interfacesRed;
    }
}