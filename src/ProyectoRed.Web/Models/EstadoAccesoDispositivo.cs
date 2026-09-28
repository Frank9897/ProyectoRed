namespace ProyectoRed.Web.Models;

public class EstadoAccesoDispositivo
{
    public bool PuedeAbrirInterfaz { get; set; }

    public bool MismaRed { get; set; }

    public bool UsaDhcp { get; set; }

    public string DireccionIPLocal { get; set; } = string.Empty;

    public string MascaraRedLocal { get; set; } = string.Empty;

    public string UrlInterfaz { get; set; } = string.Empty;

    public string Mensaje { get; set; } = string.Empty;

    public ConfiguracionManualRed ConfiguracionManual { get; set; } =
        new ConfiguracionManualRed();
}
