namespace ProyectoRed.Web.Models;

public class MetodoAccesoDispositivo
{
    /// <summary>
    /// Nombre que se muestra al técnico, por ejemplo HTTP, HTTPS o SSH.
    /// Cambiarlo solo modifica la etiqueta visual del método detectado.
    /// </summary>
    public string Nombre { get; set; } = string.Empty;

    /// <summary>
    /// Protocolo que fue comprobado por el servicio.
    /// Cambiarlo afecta la clasificación que utiliza el servicio para
    /// decidir qué prueba de red debe realizar.
    /// </summary>
    public string Protocolo { get; set; } = string.Empty;

    /// <summary>
    /// Puerto TCP asociado al método de acceso.
    /// Cambiarlo modifica el puerto que ProyectoRed intenta comprobar.
    /// </summary>
    public int Puerto { get; set; }

    /// <summary>
    /// Indica si el protocolo respondió en el puerto comprobado.
    /// Cambiarlo manualmente alteraría el resultado que verá la interfaz.
    /// </summary>
    public bool Disponible { get; set; }

    /// <summary>
    /// URL que puede abrirse directamente cuando el método es HTTP o HTTPS.
    /// Cambiarla modifica el destino que utiliza el botón de apertura web.
    /// </summary>
    public string Url { get; set; } = string.Empty;

    /// <summary>
    /// Comando de consola útil para métodos como SSH o Telnet.
    /// Cambiarlo modifica el texto que se copia al portapapeles del técnico.
    /// </summary>
    public string Comando { get; set; } = string.Empty;
}
