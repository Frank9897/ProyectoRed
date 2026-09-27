@echo off
setlocal

set "PROYECTO=%~dp0src\ProyectoRed.Web\ProyectoRed.Web.csproj"
set "SALIDA=%~dp0dist\windows-x64"

echo ==========================================
echo       Publicar ProyectoRed - Windows x64
echo ==========================================
echo.
echo Limpiando salida anterior...
if exist "%SALIDA%" rmdir /s /q "%SALIDA%"

echo.
echo Publicando self-contained + single-file...
dotnet publish "%PROYECTO%" -c Release -p:PublishProfile=WindowsSelfContained -p:PublishDir="%SALIDA%\"

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
echo Ejecutable:
echo %SALIDA%\ProyectoRed.Web.exe
echo.
echo Para crear el instalador:
echo installer\crear-instalador-windows.bat
echo.

pause