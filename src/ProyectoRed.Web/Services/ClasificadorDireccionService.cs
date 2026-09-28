using System.Net;
using System.Net.Sockets;

namespace ProyectoRed.Web.Services;

public class ClasificadorDireccionService
{
    public string Clasificar(string direccionIP)
    {
        if (!IPAddress.TryParse(
                direccionIP,
                out IPAddress direccion) ||
            direccion.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new InvalidOperationException(
                "La dirección IP no es una IPv4 válida.");
        }

        byte[] bytes =
            direccion.GetAddressBytes();

        byte primerOcteto = bytes[0];
        byte segundoOcteto = bytes[1];

        if (direccion.Equals(IPAddress.Any))
        {
            return "IPv4 no especificada";
        }

        if (primerOcteto == 127)
        {
            return "IPv4 de loopback";
        }

        if (primerOcteto == 169 &&
            segundoOcteto == 254)
        {
            return "IPv4 Link-Local";
        }

        if (primerOcteto == 10)
        {
            return "IPv4 privada";
        }

        if (primerOcteto == 172 &&
            segundoOcteto >= 16 &&
            segundoOcteto <= 31)
        {
            return "IPv4 privada";
        }

        if (primerOcteto == 192 &&
            segundoOcteto == 168)
        {
            return "IPv4 privada";
        }

        if (primerOcteto >= 224 &&
            primerOcteto <= 239)
        {
            return "IPv4 multicast";
        }

        return "IPv4 pública/global";
    }
}
