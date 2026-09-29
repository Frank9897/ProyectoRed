@echo off
setlocal EnableExtensions

fltmc >nul 2>&1
if errorlevel 1 (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

title ProyectoRed - Diagnostico con Windows
color 0A
cls

echo.
echo ============================================================
echo                 PROYECTORED
echo          DIAGNOSTICO NATIVO DE WINDOWS
echo ============================================================
echo.
echo La prueba consulta UNICAMENTE la interfaz Ethernet fisica
echo que Windows detecta como conectada.
echo.
echo No escanea subredes.
echo No hace ping a direcciones desconocidas.
echo No selecciona arbitrariamente un vecino.
echo.
echo IMPORTANTE:
echo Windows no tiene un comando nativo que garantice que una
echo IP/MAC aprendida por ARP pertenece al equipo del extremo
echo fisico del cable UTP.
echo.
echo ============================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='SilentlyContinue'; $adaptadores=@(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.MediaConnectionState -eq 'Connected' }); if($adaptadores.Count -ne 1){ Write-Host 'SIN RESULTADO'; if($adaptadores.Count -eq 0){ Write-Host 'No se encontro una unica interfaz Ethernet fisica conectada.' } else { Write-Host ('Windows detecta ' + $adaptadores.Count + ' interfaces fisicas conectadas.') }; exit }; $adaptador=$adaptadores[0]; $vecinos=@(Get-NetNeighbor -InterfaceIndex $adaptador.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' -and $_.IPAddress -notmatch '^(127\.|224\.|225\.|226\.|227\.|228\.|229\.|230\.|231\.|232\.|233\.|234\.|235\.|236\.|237\.|238\.|239\.|255\.)' } | Sort-Object IPAddress); if($vecinos.Count -eq 1){ Write-Host 'RESULTADO'; Write-Host ('IP : ' + $vecinos[0].IPAddress); Write-Host ('MAC: ' + $vecinos[0].LinkLayerAddress.ToUpper()) } elseif($vecinos.Count -eq 0){ Write-Host 'SIN RESULTADO'; Write-Host 'Windows no conoce ningun vecino IPv4 util en esa interfaz.' } else { Write-Host 'SIN RESULTADO UNICO'; Write-Host ('Windows conoce ' + $vecinos.Count + ' vecinos IPv4 en esa interfaz.'); Write-Host 'No se seleccionara ninguno para evitar un falso positivo.' }"

echo.
echo ============================================================
echo.
pause

endlocal
