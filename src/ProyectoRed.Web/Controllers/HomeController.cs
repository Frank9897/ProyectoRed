using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using ProyectoRed.Web.Models;
using ProyectoRed.Web.Services;
namespace ProyectoRed.Web.Controllers;

public class HomeController : Controller
{
    private readonly InterfazRedService _interfazRedService;
    private readonly CapturadorPaquetesService _capturadorPaquetesService;

    public HomeController(InterfazRedService interfazRedService, CapturadorPaquetesService capturadorPaquetesService)
    {
        _capturadorPaquetesService = capturadorPaquetesService;
        _interfazRedService = interfazRedService;
    }
    public IActionResult Index()
    {
        List<InterfazRed> interfacesList = _interfazRedService.ObtenerInterfaces();
        return View(interfacesList);
    }


    public IActionResult PruebaCaptura(string nombreInterfaz)
    {
        _capturadorPaquetesService.Capturar(nombreInterfaz);

        return Content("Prueba de captura ejecutada.");
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
