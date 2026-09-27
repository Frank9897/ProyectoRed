namespace ProyectoRed.Web.Models;
public class InterfazRed
{
    public string Nombre { get; set; }
    public string DireccionIP { get; set; }
    public string DireccionMac { get; set; }
    public string Tipo { get; set; }                                         
    
    public InterfazRed(string nombre, string direccionIP, string direccionMac, string tipo)
    {
        Nombre = nombre;
        DireccionIP = direccionIP;
        DireccionMac = direccionMac;
        Tipo = tipo;
    }
}