using System.Diagnostics;
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

    public async Task<IActionResult> Descubrir(string nombreInterfaz)
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
            DispositivoDetectado resultado =
                await _capturadorPaquetesService.CapturarAsync(
                    nombreInterfaz);

            string clasificacionDireccion = string.Empty;

            if (!string.IsNullOrWhiteSpace(resultado.DireccionIP))
            {
                clasificacionDireccion =
                    _clasificadorDireccionService.Clasificar(
                        resultado.DireccionIP);
            }

            return Json(new
            {
                direccionIP = resultado.DireccionIP,
                direccionMac = resultado.DireccionMac,
                nombre = resultado.Nombre,
                tipoDireccionIP = clasificacionDireccion
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
    public IActionResult AccesoDispositivo(
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
                _accesoDispositivoService.Evaluar(
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
        return await Descubrir(nombreInterfaz);
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
