using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using ProyectoRed.Web.Models;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ProyectoRed.Web.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        // Obtenemos las interfaces de red disponibles actualmente.
        NetworkInterface[] interfaces =
            NetworkInterface.GetAllNetworkInterfaces();
        
        List<NetworkInterface> interfacesList = new List<NetworkInterface>();

        // Recorremos cada interfaz.
        foreach (NetworkInterface interfaz in interfaces)
        {
            // Solo trabajamos con interfaces que están activas.
            if (interfaz.OperationalStatus != OperationalStatus.Up || interfaz.NetworkInterfaceType != NetworkInterfaceType.Ethernet)
            {
                continue;
            }

            // Nombre de la interfaz, por ejemplo: Ethernet.
            string nombreInterfaz = interfaz.Name;

            // Descripción proporcionada por el sistema operativo.
            string descripcion = interfaz.Description;

            // Obtenemos la dirección MAC de la interfaz.
            PhysicalAddress direccionMac =
                interfaz.GetPhysicalAddress();
            string macFormateada = BitConverter.ToString(direccionMac.GetAddressBytes()).Replace("-", ":");

            // Obtenemos las propiedades IP de la interfaz.
            IPInterfaceProperties propiedadesIp =
                interfaz.GetIPProperties();
            string tipo = interfaz.NetworkInterfaceType.ToString();
            Console.WriteLine("----------------------------------------");
            Console.WriteLine($"Interfaz: {nombreInterfaz}");
            Console.WriteLine($"Descripción: {descripcion}");
            Console.WriteLine($"Tipo: {tipo}");
            Console.WriteLine($"MAC: {macFormateada}");

            // Recorremos las direcciones asociadas a la interfaz.
            foreach (UnicastIPAddressInformation direccion
                     in propiedadesIp.UnicastAddresses)
            {
                // Solo mostramos direcciones IPv4.
                if (direccion.Address.AddressFamily ==
                    AddressFamily.InterNetwork)
                {
                    string direccionIp =
                        direccion.Address.ToString();

                    Console.WriteLine($"IPv4: {direccionIp}");
                }
            }
            interfacesList.Add(interfaz);
        }


        return View(interfacesList);
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
