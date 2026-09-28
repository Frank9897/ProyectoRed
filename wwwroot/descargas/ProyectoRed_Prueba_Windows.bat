@echo off
setlocal

title ProyectoRed - Prueba con Windows
color 0A

echo.
echo ============================================================
echo                 PROYECTORED
echo             PRUEBA CON WINDOWS
echo ============================================================
echo.
echo Buscando un unico vecino IPv4 en la interfaz Ethernet fisica.
echo No se escanea una subred y no se consultan otras interfaces.
echo.
echo Importante: Windows no puede garantizar por si solo que un
echo vecino ARP sea fisicamente el equipo del extremo del UTP.
echo Por eso este script NO muestra un resultado si encuentra
echo varios vecinos.
echo.

fltmc >nul 2>&1
if errorlevel 1 (
    color 0E
    echo EJECUTE ESTE ARCHIVO COMO ADMINISTRADOR.
    echo.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"$ErrorActionPreference='SilentlyContinue'; ^
$adaptadores=@(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.MediaConnectionState -eq 'Connected' -and $_.HardwareInterface -eq $true }); ^
if($adaptadores.Count -ne 1){ ^
  if($adaptadores.Count -eq 0){ ^
    Write-Host 'SIN RESULTADO'; ^
    Write-Host 'No se encontro una unica interfaz Ethernet fisica conectada.' ^
  } else { ^
    Write-Host 'SIN RESULTADO'; ^
    Write-Host 'Hay varias interfaces Ethernet fisicas conectadas. Desactive las que no correspondan y repita la prueba.' ^
  }; ^
  exit 0 ^
}; ^
$adaptador=$adaptadores[0]; ^
$ipLocal=@(Get-NetIPAddress -InterfaceIndex $adaptador.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' } | Select-Object -First 1 -ExpandProperty IPAddress); ^
$gateway=@(Get-NetRoute -InterfaceIndex $adaptador.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,Metric | Select-Object -First 1 -ExpandProperty NextHop); ^
netsh interface ipv4 delete arpcache name=\"$($adaptador.Name)\" store=active | Out-Null; ^
Start-Sleep -Seconds 5; ^
$vecinos=@(Get-NetNeighbor -InterfaceIndex $adaptador.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { ^
  $_.LinkLayerAddress -and ^
  $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and ^
  $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' -and ^
  $_.IPAddress -notmatch '^(127\.|224\.|225\.|226\.|227\.|228\.|229\.|230\.|231\.|232\.|233\.|234\.|235\.|236\.|237\.|238\.|239\.|255\.)' -and ^
  (-not $ipLocal -or $_.IPAddress -ne $ipLocal[0]) -and ^
  (-not $gateway -or $_.IPAddress -ne $gateway[0]) ^
} | Sort-Object IPAddress); ^
if($vecinos.Count -eq 1){ ^
  Write-Host 'RESULTADO'; ^
  Write-Host ('IP : ' + $vecinos[0].IPAddress); ^
  Write-Host ('MAC: ' + $vecinos[0].LinkLayerAddress) ^
} elseif($vecinos.Count -eq 0){ ^
  Write-Host 'SIN RESULTADO'; ^
  Write-Host 'Windows no encontro un vecino IPv4 unico distinto de la puerta de enlace.' ^
} else { ^
  Write-Host 'SIN RESULTADO UNICO'; ^
  Write-Host ('Windows conoce ' + $vecinos.Count + ' vecinos IPv4 en esa interfaz. No se seleccionara uno para evitar un falso positivo.') ^
}"

echo.
echo ============================================================
echo.
pause

endlocal
