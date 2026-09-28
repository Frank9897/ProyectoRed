@echo off
setlocal EnableExtensions

fltmc >nul 2>&1
if errorlevel 1 (
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

title ProyectoRed - Prueba con Windows
color 0A
cls

echo.
echo ============================================================
echo                 PROYECTORED
echo             PRUEBA CON WINDOWS
echo ============================================================
echo.
echo Esta prueba busca una unica relacion IP + MAC
echo aprendida por Windows en una interfaz fisica Ethernet.
echo No escanea subredes y no consulta una IP indicada.
echo.
echo ============================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $adaptadores=@(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.MediaConnectionState -eq 'Connected' }); if($adaptadores.Count -ne 1){ Write-Host 'SIN RESULTADO'; if($adaptadores.Count -eq 0){ Write-Host 'No hay una unica interfaz Ethernet fisica conectada.' } else { Write-Host 'Hay varias interfaces Ethernet fisicas conectadas.'; Write-Host 'Desactive las que no correspondan y repita la prueba.' }; exit }; $adaptador=$adaptadores[0]; & netsh interface ipv4 delete arpcache name='$($adaptador.Name)' store=active | Out-Null; Start-Sleep -Seconds 5; $vecinos=@(Get-NetNeighbor -InterfaceIndex $adaptador.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' -and $_.IPAddress -notmatch '^(127\.|224\.|225\.|226\.|227\.|228\.|229\.|230\.|231\.|232\.|233\.|234\.|235\.|236\.|237\.|238\.|239\.|255\.)' } | Sort-Object IPAddress); if($vecinos.Count -eq 1){ Write-Host 'RESULTADO'; Write-Host ('IP : ' + $vecinos[0].IPAddress); Write-Host ('MAC: ' + $vecinos[0].LinkLayerAddress.ToUpper()) } elseif($vecinos.Count -eq 0){ Write-Host 'SIN RESULTADO'; Write-Host 'Windows no encontro un vecino IPv4 unico.' } else { Write-Host 'SIN RESULTADO UNICO'; Write-Host ('Windows conoce ' + $vecinos.Count + ' vecinos IPv4 en esa interfaz.') }"

echo.
echo ============================================================
echo.
pause

endlocal
