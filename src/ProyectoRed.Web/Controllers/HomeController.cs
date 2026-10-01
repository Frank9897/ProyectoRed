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
    private readonly IWebHostEnvironment _entornoWeb;

    public HomeController(
        InterfazRedService interfazRedService,
        CapturadorPaquetesService capturadorPaquetesService,
        AccesoDispositivoService accesoDispositivoService,
        ClasificadorDireccionService clasificadorDireccionService,
        HistorialDispositivosService historialDispositivosService,
        IWebHostEnvironment entornoWeb)
    {
        _capturadorPaquetesService = capturadorPaquetesService;
        _accesoDispositivoService = accesoDispositivoService;
        _clasificadorDireccionService = clasificadorDireccionService;
        _interfazRedService = interfazRedService;
        _historialDispositivosService = historialDispositivosService;
        _entornoWeb = entornoWeb;
    }

    public IActionResult Index()
    {
        List<InterfazRed> interfacesList =
            _interfazRedService.ObtenerInterfaces();

        return View(interfacesList);
    }

    public async Task<IActionResult> Descubrir(
        string nombreInterfaz,
        string direccionIPObjetivo)
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
                    direccionIPObjetivo);

            string clasificacionDireccion = string.Empty;

            if (!string.IsNullOrWhiteSpace(resultado.DireccionIP))
            {
                clasificacionDireccion =
                    _clasificadorDireccionService.Clasificar(
                        resultado.DireccionIP);
            }

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
                else if (!string.IsNullOrWhiteSpace(direccionIPObjetivo))
                {
                    mensajeEstado =
                        $"El enlace UTP está activo, pero no hubo respuesta ARP de {direccionIPObjetivo}.";
                }
                else
                {
                    mensajeEstado =
                        string.Equals(
                            _capturadorPaquetesService.UltimoOrigenDeteccion,
                            "ARP",
                            StringComparison.OrdinalIgnoreCase)
                            ? "El enlace UTP está activo y se observaron respuestas ARP, " +
                              "pero no hubo un candidato único y estable para identificar el dispositivo."
                            : "El enlace UTP está activo, pero no se obtuvo una respuesta del dispositivo " +
                              "mediante LLDP, CDP, STP o ARP durante la búsqueda automática.";
                }
            }
            else if (string.IsNullOrWhiteSpace(resultado.DireccionIP))
            {
                mensajeEstado =
                    "Se identificó el vecino Ethernet, pero no se obtuvo una IPv4. " +
                    "El dispositivo puede no anunciar una dirección de gestión.";
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
                tipoDireccionIP = clasificacionDireccion,
                metodoDeteccion =
                    string.IsNullOrWhiteSpace(metodoDeteccion)
                        ? "Detección automática"
                        : metodoDeteccion,
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
                StringComparison.OrdinalIgnoreCase))
        {
            return origen +
                   " (vecino directo)";
        }

        if (origen.Equals(
                "ARP",
                StringComparison.OrdinalIgnoreCase))
        {
            return tieneResultado
                ? "ARP (sin confirmación de vecino directo)"
                : "ARP (candidatos múltiples o sin confirmación)";
        }

        return origen;
    }

    [HttpGet]
    public IActionResult DescargarPruebaWindows()
    {
        string ruta =
            Path.Combine(
                _entornoWeb.WebRootPath,
                "descargas",
                "ProyectoRed_Prueba_Windows.bat");

        if (!System.IO.File.Exists(ruta))
        {
            return NotFound();
        }

        return PhysicalFile(
            ruta,
            "application/octet-stream",
            "ProyectoRed_Prueba_Windows.bat");
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
