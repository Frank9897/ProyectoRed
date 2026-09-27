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

rem Permitir indicar manualmente la ubicacion si Inno no esta en PATH.
if defined ISCC_PATH if exist "%ISCC_PATH%" set "ISCC=%ISCC_PATH%"

rem Buscar ISCC en PATH.
if not defined ISCC (
    for /f "delims=" %%I in ('where ISCC.exe 2^>nul') do (
        if not defined ISCC set "ISCC=%%I"
    )
)

rem Rutas habituales de instalacion de Inno Setup 6.
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"

rem Ultimo intento: buscar ISCC.exe dentro de las carpetas de programas.
if not defined ISCC (
    if exist "%ProgramFiles(x86)%" (
        for /f "delims=" %%I in ('where /r "%ProgramFiles(x86)%" ISCC.exe 2^>nul') do (
            if not defined ISCC set "ISCC=%%I"
        )
    )
)

if not defined ISCC (
    if exist "%ProgramFiles%" (
        for /f "delims=" %%I in ('where /r "%ProgramFiles%" ISCC.exe 2^>nul') do (
            if not defined ISCC set "ISCC=%%I"
        )
    )
)

if not defined ISCC (
    echo ERROR: No se encontro ISCC.exe de Inno Setup 6.
    echo.
    echo Compruebe que exista uno de estos archivos:
    echo   %ProgramFiles(x86)%\Inno Setup 6\ISCC.exe
    echo   %ProgramFiles%\Inno Setup 6\ISCC.exe
    echo.
    echo Tambien puede indicar la ruta manualmente con:
    echo   set ISCC_PATH=C:\ruta\a\ISCC.exe
    echo.
    pause
    exit /b 1
)

echo Compilador encontrado:
echo %ISCC%
echo.
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