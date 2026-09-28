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
echo Esta prueba usa solamente herramientas nativas de Windows.
echo No escanea subredes ni consulta una IP indicada por el usuario.
echo Si Windows conoce varios vecinos, no selecciona ninguno.
echo.
echo EJECUTAR COMO ADMINISTRADOR
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
$adaptadores=@(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.MediaConnectionState -eq 'Connected' }); ^
if($adaptadores.Count -ne 1){ ^
  Write-Host 'SIN RESULTADO'; ^
  if($adaptadores.Count -eq 0){ ^
    Write-Host 'No se encontro una unica interfaz de red fisica conectada.' ^
  } else { ^
    Write-Host 'Hay varias interfaces de red fisicas conectadas. Desactive las que no correspondan y repita la prueba.' ^
  }; ^
  exit 0 ^
}; ^
$adaptador=$adaptadores[0]; ^
netsh interface ipv4 delete arpcache name='$($adaptador.Name)' store=active | Out-Null; ^
Start-Sleep -Seconds 5; ^
$vecinos=@(Get-NetNeighbor -InterfaceIndex $adaptador.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { ^
  $_.LinkLayerAddress -and ^
  $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and ^
  $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' -and ^
  $_.IPAddress -notmatch '^(127\.|224\.|225\.|226\.|227\.|228\.|229\.|230\.|231\.|232\.|233\.|234\.|235\.|236\.|237\.|238\.|239\.|255\.)' ^
} | Sort-Object IPAddress); ^
if($vecinos.Count -eq 1){ ^
  Write-Host 'RESULTADO'; ^
  Write-Host ('IP : ' + $vecinos[0].IPAddress); ^
  Write-Host ('MAC: ' + $vecinos[0].LinkLayerAddress.ToUpper()) ^
} elseif($vecinos.Count -eq 0){ ^
  Write-Host 'SIN RESULTADO'; ^
  Write-Host 'Windows no encontro un vecino IPv4 en la interfaz Ethernet despues de limpiar la cache.' ^
} else { ^
  Write-Host 'SIN RESULTADO UNICO'; ^
  Write-Host ('Windows conoce ' + $vecinos.Count + ' vecinos IPv4 en esa interfaz. No se seleccionara uno para evitar un falso positivo.') ^
}"

echo.
echo ============================================================
echo.
pause

endlocal
