using System.Diagnostics;
using System.Net.NetworkInformation;
using Microsoft.AspNetCore.Mvc;
using ProyectoRed.Web.Models;
using ProyectoRed.Web.Services;

namespace ProyectoRed.Web.Controllers;

public class HomeController : Controller
{
    private readonly InterfazRedService _interfazRedService;
    private readonly CapturadorPaquetesService _capturadorPaquetesService;
    private readonly AccesoDispositivoService _accesoDispositivoService;
    private readonly ClasificadorDireccionService _clasificadorDireccionService;
    private readonly HistorialDispositivosService _historialDispositivosService;

    public HomeController(
        InterfazRedService interfazRedService,
        CapturadorPaquetesService capturadorPaquetesService,
        AccesoDispositivoService accesoDispositivoService,
        ClasificadorDireccionService clasificadorDireccionService,
        HistorialDispositivosService historialDispositivosService)
    {
        _capturadorPaquetesService = capturadorPaquetesService;
        _accesoDispositivoService = accesoDispositivoService;
        _clasificadorDireccionService = clasificadorDireccionService;
        _interfazRedService = interfazRedService;
        _historialDispositivosService = historialDispositivosService;
    }

    public IActionResult Index()
    {
        List<InterfazRed> interfacesList =
            _interfazRedService.ObtenerInterfaces();

        return View(interfacesList);
    }

    public async Task<IActionResult> Descubrir(
        string nombreInterfaz,
        string direccionIPObjetivo,
        string direccionMacObjetivo)
    {
        if (string.IsNullOrWhiteSpace(nombreInterfaz))
        {
            return BadRequest(new
            {
                mensaje = "Debe seleccionar una interfaz de red."
            });
        }

        try
        {
            NetworkInterface interfazRed =
                NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(interfaz =>
                        string.Equals(
                            interfaz.Name,
                            nombreInterfaz,
                            StringComparison.OrdinalIgnoreCase));

            bool enlaceActivo =
                interfazRed != null &&
                interfazRed.OperationalStatus ==
                OperationalStatus.Up;

            DispositivoDetectado resultado =
                await _capturadorPaquetesService.CapturarAsync(
                    nombreInterfaz,
                    direccionIPObjetivo,
                    direccionMacObjetivo);

            string clasificacionDireccion = string.Empty;

            if (!string.IsNullOrWhiteSpace(resultado.DireccionIP))
            {
                clasificacionDireccion =
                    _clasificadorDireccionService.Clasificar(
                        resultado.DireccionIP);
            }

            string mascaraLocal =
                interfazRed?
                    .GetIPProperties()
                    .UnicastAddresses
                    .FirstOrDefault(
                        direccion =>
                            direccion.Address.AddressFamily ==
                            System.Net.Sockets.AddressFamily.InterNetwork)
                    ?.IPv4Mask
                    ?.ToString()
                    ?? string.Empty;

            string mensajeEstado = string.Empty;

            string metodoDeteccion =
                TraducirMetodoDeteccion(
                    _capturadorPaquetesService.UltimoOrigenDeteccion,
                    !string.IsNullOrWhiteSpace(
                        resultado.DireccionIP));

            if (string.IsNullOrWhiteSpace(resultado.DireccionMac))
            {
                if (!enlaceActivo)
                {
                    mensajeEstado =
                        "La interfaz Ethernet no tiene un enlace activo.";
                }
                else if (!string.IsNullOrWhiteSpace(direccionMacObjetivo))
                {
                    mensajeEstado =
                        $"El enlace UTP está activo, pero no se encontró una respuesta asociada a la MAC {direccionMacObjetivo}.";
                }
                else if (!string.IsNullOrWhiteSpace(direccionIPObjetivo))
                {
                    mensajeEstado =
                        $"El enlace UTP está activo, pero no hubo respuesta ARP de {direccionIPObjetivo}.";
                }
                else
                {
                    mensajeEstado =
                        "No se pudo identificar el dispositivo conectado. " +
                        "No se encontró una MAC ni una IPv4 con las señales disponibles.";
                }
            }
            else if (string.IsNullOrWhiteSpace(resultado.DireccionIP))
            {
                mensajeEstado =
                    "No se pudo confirmar una IPv4 del dispositivo. " +
                    "Se conservó la MAC del candidato más probable como dato de diagnóstico.";
            }
            else if (_capturadorPaquetesService.UltimaConfianzaDeteccion ==
                     "Probable por heurística ARP" ||
                     _capturadorPaquetesService.UltimaConfianzaDeteccion ==
                     "Posible: candidato más probable" ||
                     _capturadorPaquetesService.UltimaConfianzaDeteccion ==
                     "Baja: candidato más probable")
            {
                mensajeEstado =
                    "Se seleccionó la IPv4 con mayor evidencia disponible entre las respuestas ARP. " +
                    "La confianza indica una inferencia del programa y no una confirmación de vecino directo.";
            }
            else if (_capturadorPaquetesService.UltimoUsoHistorial)
            {
                mensajeEstado =
                    "Se reutilizó la MAC registrada en el historial y se buscó su IPv4 actual.";
            }
            else if (_capturadorPaquetesService.UltimoCriterioBusqueda == "MAC")
            {
                mensajeEstado =
                    "Se identificó el dispositivo mediante la MAC indicada.";
            }
            else if (_capturadorPaquetesService.UltimoCriterioBusqueda == "IP")
            {
                mensajeEstado =
                    "Se identificó el dispositivo mediante la IP indicada.";
            }
            else
            {
                mensajeEstado =
                    "Se identificó el dispositivo automáticamente.";
            }

            return Json(new
            {
                enlaceActivo,
                direccionIP = resultado.DireccionIP,
                direccionMac = resultado.DireccionMac,
                nombre = resultado.Nombre,
                fabricante = _capturadorPaquetesService.UltimoFabricanteDeteccion,
                criterioBusqueda = _capturadorPaquetesService.UltimoCriterioBusqueda,
                usoHistorial = _capturadorPaquetesService.UltimoUsoHistorial,
                tipoDireccionIP = clasificacionDireccion,
                mascaraLocal = mascaraLocal,
                confianzaDeteccion =
                    string.IsNullOrWhiteSpace(
                        _capturadorPaquetesService.UltimaConfianzaDeteccion)
                        ? "No determinada"
                        : _capturadorPaquetesService.UltimaConfianzaDeteccion,
                puntajeDeteccion =
                    _capturadorPaquetesService.UltimoPuntajeDeteccion,
                razonDeteccion =
                    _capturadorPaquetesService.UltimaRazonDeteccion,
                metodoDeteccion =
                    string.IsNullOrWhiteSpace(metodoDeteccion)
                        ? "Detección automática"
                        : metodoDeteccion,
                faseDeteccion =
                    _capturadorPaquetesService.UltimaFaseDeteccion,
                tiempoTranscurridoMs =
                    _capturadorPaquetesService.UltimaDuracionDeteccionMs,
                tiempoEstimadoMs =
                    _capturadorPaquetesService.UltimaEstimacionDeteccionMs,
                cantidadSondasArp =
                    _capturadorPaquetesService.UltimaCantidadSondasArp,
                mensajeEstado
            });
        }
        catch (DllNotFoundException)
        {
            return StatusCode(503, new
            {
                mensaje =
                    "No se encontró Npcap. Instale Npcap para habilitar la captura Ethernet."
            });
        }
        catch (InvalidOperationException excepcion)
        {
            return BadRequest(new
            {
                mensaje = excepcion.Message
            });
        }
    }

    [HttpGet]
    public async Task<IActionResult> AccesoDispositivo(
        string nombreInterfaz,
        string direccionIP)
    {
        if (string.IsNullOrWhiteSpace(nombreInterfaz) ||
            string.IsNullOrWhiteSpace(direccionIP))
        {
            return BadRequest(new
            {
                mensaje =
                    "Se necesita la interfaz de red y la IP del dispositivo."
            });
        }

        try
        {
            EstadoAccesoDispositivo resultado =
                await _accesoDispositivoService.EvaluarAsync(
                    nombreInterfaz,
                    direccionIP);

            return Json(resultado);
        }
        catch (InvalidOperationException excepcion)
        {
            return BadRequest(new
            {
                mensaje = excepcion.Message
            });
        }
    }

    // Se conserva esta ruta para las pruebas directas que veníamos utilizando.
    public async Task<IActionResult> PruebaCaptura(string nombreInterfaz)
    {
        return await Descubrir(
            nombreInterfaz,
            string.Empty,
            string.Empty);
    }

    private string TraducirMetodoDeteccion(
        string origen,
        bool tieneResultado)
    {
        if (string.IsNullOrWhiteSpace(origen))
        {
            return "Búsqueda automática";
        }

        if (origen.Contains(
                "LLDP",
                StringComparison.OrdinalIgnoreCase) ||
            origen.Contains(
                "CDP",
                StringComparison.OrdinalIgnoreCase) ||
            origen.Contains(
                "STP",
                StringComparison.OrdinalIgnoreCase) ||
            origen.Contains(
                "EDP",
                StringComparison.OrdinalIgnoreCase) ||
            origen.Contains(
                "FDP",
                StringComparison.OrdinalIgnoreCase))
        {
            return origen +
                   " (vecino directo)";
        }

        if (origen.Equals(
                "ARP",
                StringComparison.OrdinalIgnoreCase))
        {
            if (_capturadorPaquetesService.UltimaConfianzaDeteccion ==
                "Probable por heurística ARP")
            {
                return "ARP (candidato probable)";
            }

            if (_capturadorPaquetesService.UltimaConfianzaDeteccion ==
                "Posible: candidato más probable")
            {
                return "ARP (candidato más probable)";
            }

            if (_capturadorPaquetesService.UltimaConfianzaDeteccion ==
                "Baja: candidato más probable")
            {
                return "ARP (candidato de baja confianza)";
            }

            if (_capturadorPaquetesService.UltimaConfianzaDeteccion ==
                "Candidato observado")
            {
                return "ARP (MAC observada; IP no confirmada)";
            }

            return tieneResultado
                ? "ARP (sin confirmación de vecino directo)"
                : "ARP (sin candidato confirmado)";
        }

        return origen;
    }

    [HttpGet]
    public async Task<IActionResult> Historial()
    {
        List<RegistroDispositivo> historial =
            await _historialDispositivosService.ObtenerHistorialAsync();

        return Json(historial);
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(
        Duration = 0,
        Location = ResponseCacheLocation.None,
        NoStore = true)]
    public IActionResult Error()
    {
        return View(
            new ErrorViewModel
            {
                RequestId =
                    Activity.Current?.Id ??
                    HttpContext.TraceIdentifier
            });
    }
}
