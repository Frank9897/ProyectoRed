namespace ProyectoRed.Web.Services;

public sealed class FabricanteMacService
{
    private static readonly Dictionary<string, (string Fabricante, bool Infraestructura)> Ouis =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // Cisco Systems.
            ["00:00:0C"] = ("Cisco Systems", true),

            // Extreme Networks.
            ["00:01:30"] = ("Extreme Networks", true),
            ["00:04:96"] = ("Extreme Networks", true),
            ["00:E0:2B"] = ("Extreme Networks", true),
            ["5C:0E:8B"] = ("Extreme Networks", true),
            ["74:67:F7"] = ("Extreme Networks", true),
            ["94:9B:2C"] = ("Extreme Networks", true),
            ["A4:EA:8E"] = ("Extreme Networks", true),
            ["B4:2D:56"] = ("Extreme Networks", true),
            ["B4:C7:99"] = ("Extreme Networks", true),
            ["B8:50:01"] = ("Extreme Networks", true),
            ["D8:84:66"] = ("Extreme Networks", true),
            ["FC:0A:81"] = ("Extreme Networks", true),
            ["0E:04:96"] = ("Extreme Networks", true),

            // HPE / Aruba.
            ["00:1A:1E"] = ("HPE / Aruba", true),
            ["00:0B:86"] = ("HPE / Aruba", true),
            ["D8:C7:C8"] = ("HPE / Aruba", true),
            ["6C:F3:7F"] = ("HPE / Aruba", true),
            ["24:DE:C6"] = ("HPE / Aruba", true),
            ["9C:1C:12"] = ("HPE / Aruba", true),
            ["18:64:72"] = ("HPE / Aruba", true),

            // TP-Link. Incluye el OUI observado en las pruebas del proyecto.
            ["60:A4:B7"] = ("TP-Link Systems", true),

            // Foundry / Brocade / Ruckus FastIron.
            ["00:E0:52"] = ("Foundry / Ruckus", true)
        };

    public string ObtenerFabricante(string direccionMac)
    {
        string oui =
            ObtenerOui(
                direccionMac);

        return Ouis.TryGetValue(
            oui,
            out (string Fabricante, bool Infraestructura) datos)
            ? datos.Fabricante
            : "Fabricante no identificado por OUI";
    }

    public bool EsFabricanteInfraestructura(string direccionMac)
    {
        string oui =
            ObtenerOui(
                direccionMac);

        return Ouis.TryGetValue(
            oui,
            out (string Fabricante, bool Infraestructura) datos) &&
               datos.Infraestructura;
    }

    private string ObtenerOui(string direccionMac)
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

        if (limpio.Length < 6)
        {
            return string.Empty;
        }

        return
            $"{limpio[0]}{limpio[1]}:" +
            $"{limpio[2]}{limpio[3]}:" +
            $"{limpio[4]}{limpio[5]}";
    }
}
