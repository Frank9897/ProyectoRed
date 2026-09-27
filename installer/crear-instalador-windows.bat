@echo off
setlocal

set "RAIZ=%~dp0.."
set "PUBLICACION=%RAIZ%\dist\windows-x64"
set "SCRIPT=%~dp0ProyectoRed.iss"
set "ISCC="

echo ==========================================
echo     Crear instalador ProyectoRed
echo ==========================================
echo.

if not exist "%PUBLICACION%\ProyectoRed.Web.exe" (
    echo ERROR: No existe la publicacion:
    echo %PUBLICACION%\ProyectoRed.Web.exe
    echo.
    echo Ejecute primero:
    echo publicar-windows.bat
    echo.
    pause
    exit /b 1
)

where ISCC.exe >nul 2>&1
if not errorlevel 1 (
    set "ISCC=ISCC.exe"
)

if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" (
    set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
)

if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" (
    set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
)

if not defined ISCC (
    echo ERROR: No se encontro Inno Setup 6.
    echo Instale Inno Setup en la PC de desarrollo y vuelva a intentarlo.
    echo.
    pause
    exit /b 1
)

echo Compilando instalador...
"%ISCC%" "%SCRIPT%"

if errorlevel 1 (
    echo.
    echo ERROR: La compilacion del instalador fallo.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Instalador creado correctamente.
echo ==========================================
echo.
echo Resultado:
echo %~dp0dist\ProyectoRed-Setup.exe
echo.

pause