namespace ProyectoRed.Web.Models;

public class RegistroDispositivo
{
    public string DireccionIP { get; set; } = string.Empty;
    public string DireccionMac { get; set; } = string.Empty;
    public string Nombre { get; set; } = string.Empty;
    public string NombreInterfaz { get; set; } = string.Empty;
    public string Origen { get; set; } = string.Empty; // "ARP", "LLDP" o "CDP"
    public DateTime FechaDeteccion { get; set; }
}
