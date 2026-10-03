namespace ProyectoRed.Web.Models;

public class EstadoAccesoDispositivo
{
    /// <summary>
    /// Indica si existe al menos una interfaz web detectada y lista para abrirse.
    /// Cambiar este valor cambia únicamente el estado usado por el botón web.
    /// </summary>
    public bool PuedeAbrirInterfaz { get; set; }

    /// <summary>
    /// Indica si la IP de la PC y la IP del dispositivo pertenecen a la misma
    /// subred según la máscara IPv4 local.
    /// Cambiarlo alteraría la decisión de si se realizan las pruebas de acceso.
    /// </summary>
    public bool MismaRed { get; set; }

    /// <summary>
    /// Indica si Windows tiene configurado DHCP en la interfaz seleccionada.
    /// Cambiarlo solo afecta los mensajes relacionados con la configuración local.
    /// </summary>
    public bool UsaDhcp { get; set; }

    /// <summary>
    /// Dirección IPv4 actualmente asignada a la interfaz de la PC.
    /// Cambiarla modifica el dato que se muestra como referencia de la PC.
    /// </summary>
    public string DireccionIPLocal { get; set; } = string.Empty;

    /// <summary>
    /// Máscara IPv4 local de la PC.
    /// Cambiarla modificaría la comparación de subred y el dato informativo.
    /// </summary>
    public string MascaraRedLocal { get; set; } = string.Empty;

    /// <summary>
    /// URL web detectada para el dispositivo.
    /// Cambiarla modifica el destino que utiliza el botón de apertura web.
    /// </summary>
    public string UrlInterfaz { get; set; } = string.Empty;

    /// <summary>
    /// Mensaje general que explica el resultado de la comprobación de acceso.
    /// Cambiarlo solo modifica el texto mostrado al técnico.
    /// </summary>
    public string Mensaje { get; set; } = string.Empty;

    /// <summary>
    /// Lista de métodos de administración realmente detectados sobre la IP
    /// del dispositivo. Cambiar esta lista modifica la información de acceso
    /// que se presenta en la interfaz.
    /// </summary>
    public List<MetodoAccesoDispositivo> MetodosAcceso { get; set; } =
        new List<MetodoAccesoDispositivo>();

    /// <summary>
    /// Configuración temporal que puede utilizarse para colocar a la PC en
    /// la misma red del dispositivo. Cambiarla modifica la guía de prueba.
    /// </summary>
    public ConfiguracionManualRed ConfiguracionManual { get; set; } =
        new ConfiguracionManualRed();
}
