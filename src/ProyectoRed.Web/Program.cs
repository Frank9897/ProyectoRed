using System.Diagnostics;
using ProyectoRed.Web.Services;

const string UrlLocal = "http://127.0.0.1:5094";

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls(UrlLocal);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddScoped<InterfazRedService>();
builder.Services.AddScoped<CapturadorPaquetesService>();
builder.Services.AddScoped<AccesoDispositivoService>();
builder.Services.AddScoped<ClasificadorDireccionService>();
builder.Services.AddSingleton<HistorialDispositivosService>();
builder.Services.AddSingleton<FabricanteMacService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}

app.UseRouting();

app.UseAuthorization();

// UseStaticFiles sirve directamente el contenido de wwwroot.
// Evitamos MapStaticAssets porque depende de un manifiesto de recursos
// estáticos que no necesitamos para esta aplicación MVC y que puede
// complicar una publicación single-file.
app.UseStaticFiles();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// En Windows de campo la aplicación se abre desde el navegador predeterminado.
// En Linux se mantiene el comportamiento normal de desarrollo sin abrir interfaz gráfica.
app.Lifetime.ApplicationStarted.Register(() =>
{
    if (!OperatingSystem.IsWindows())
    {
        return;
    }

    Process.Start(new ProcessStartInfo
    {
        FileName = UrlLocal,
        UseShellExecute = true
    });
});

app.Run();
