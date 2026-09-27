@echo off
setlocal

echo ==========================================
echo       Publicar ProyectoRed - Windows x64
echo ==========================================
echo.

dotnet publish "%~dp0src\ProyectoRed.Web\ProyectoRed.Web.csproj" -c Release -p:PublishProfile=WindowsSelfContained

if errorlevel 1 (
    echo.
    echo ERROR: La publicacion fallo.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Publicacion completada.
echo ==========================================
echo.
echo Resultado:
echo %~dp0src\ProyectoRed.Web\bin\Release\net10.0\win-x64\publish
echo.

pause
