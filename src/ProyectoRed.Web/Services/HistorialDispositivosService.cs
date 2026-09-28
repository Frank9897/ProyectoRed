using System.Text.Json;
using ProyectoRed.Web.Models;

namespace ProyectoRed.Web.Services;

/// <summary>
/// Guarda cada dispositivo detectado en un archivo JSON local
/// (%LOCALAPPDATA%\ProyectoRed\historial.json en Windows) para que el
/// técnico tenga, con el tiempo, un inventario pasivo de lo que fue
/// encontrando en la red sin necesidad de un escaneo activo.
/// </summary>
public class HistorialDispositivosService
{
    private readonly string _rutaArchivo;
    private readonly SemaphoreSlim _bloqueo = new(1, 1);

    public HistorialDispositivosService()
    {
        string carpetaBase =
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData);

        string carpetaApp =
            Path.Combine(carpetaBase, "ProyectoRed");

        Directory.CreateDirectory(carpetaApp);

        _rutaArchivo =
            Path.Combine(carpetaApp, "historial.json");
    }

    public async Task RegistrarAsync(RegistroDispositivo registro)
    {
        if (string.IsNullOrWhiteSpace(registro?.DireccionMac))
        {
            // No tiene sentido guardar un intento sin resultado.
            return;
        }

        await _bloqueo.WaitAsync();

        try
        {
            List<RegistroDispositivo> historial =
                await LeerSinBloqueoAsync();

            historial.Add(registro);

            string json =
                JsonSerializer.Serialize(
                    historial,
                    new JsonSerializerOptions
                    {
                        WriteIndented = true
                    });

            await File.WriteAllTextAsync(_rutaArchivo, json);
        }
        finally
        {
            _bloqueo.Release();
        }
    }

    public async Task<List<RegistroDispositivo>> ObtenerHistorialAsync()
    {
        await _bloqueo.WaitAsync();

        try
        {
            return await LeerSinBloqueoAsync();
        }
        finally
        {
            _bloqueo.Release();
        }
    }

    private async Task<List<RegistroDispositivo>> LeerSinBloqueoAsync()
    {
        if (!File.Exists(_rutaArchivo))
        {
            return new List<RegistroDispositivo>();
        }

        try
        {
            string json =
                await File.ReadAllTextAsync(_rutaArchivo);

            return JsonSerializer.Deserialize<List<RegistroDispositivo>>(json)
                ?? new List<RegistroDispositivo>();
        }
        catch (JsonException)
        {
            // Archivo corrupto: no tiramos la app, arrancamos de nuevo.
            return new List<RegistroDispositivo>();
        }
    }
}
