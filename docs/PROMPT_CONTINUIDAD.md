# Prompt de continuidad — ProyectoRed

Quiero continuar una tutoría práctica de C# y redes sobre un proyecto llamado ProyectoRed.

## Objetivo

ProyectoRed es una aplicación web local que debe ejecutarse mediante localhost en la misma PC o laptop que el técnico utiliza en el lugar donde se encuentra el dispositivo.

Escenario principal:

PC o laptop de soporte
|
| Cable UTP
v
Dispositivo cuya IP se desconoce

El dispositivo puede ser, por ejemplo, un switch administrable, una impresora IP, un plotter, una PC, una cámara u otro dispositivo de red.

La primera versión debe ser sencilla. Su objetivo es identificar, cuando sea posible:

- IP.
- MAC.
- Nombre del equipo.

No se busca inicialmente escanear una red completa, descubrir todos los dispositivos de una subred ni asumir una máscara determinada.

## Funcionamiento en campo

La aplicación debe funcionar localmente y no depender de:

- servidor Debian;
- Internet;
- Tailscale;
- Docker;
- GitHub.

El servidor Debian se utiliza para desarrollar y probar el proyecto.

La aplicación terminada debe poder publicarse como self-contained para Windows, de forma que la PC de campo no tenga que tener .NET instalado previamente.

La interfaz será una web local porque el navegador funciona como interfaz gráfica, pero la lógica C# y el acceso a la interfaz Ethernet se ejecutarán en la misma computadora que está físicamente conectada al dispositivo.

## Detección de interfaz Ethernet

La aplicación debe trabajar con la interfaz Ethernet física utilizada para la conexión UTP.

No se debe seleccionar una interfaz física mediante nombres concretos como `enp2s0`, `Ethernet` o similares, porque esos nombres pueden cambiar entre sistemas y equipos.

Tampoco se debe convertir el proyecto en un scanner de Wi-Fi, Tailscale, Docker, loopback ni otras interfaces virtuales.

### Enfoque implementado

`System.Net.NetworkInformation` se utiliza para enumerar las interfaces disponibles.

El servicio `InterfazRedService` mantiene los filtros generales:

- `OperationalStatus.Up`
- `NetworkInterfaceType.Ethernet`

Además, incorpora una comprobación específica por sistema operativo para descartar interfaces virtuales.

### Linux

En Linux se comprueba la ruta:

`/sys/class/net/<nombre>/device`

y se utiliza el vínculo hacia el dispositivo para distinguir una interfaz asociada a hardware de interfaces virtuales.

No se depende de prefijos como `enp`, `eth` o nombres similares.

### Windows

En Windows se consulta `MSFT_NetAdapter` mediante `System.Management`, utilizando:

- `ConnectorPresent = TRUE`
- `HardwareInterface = TRUE`
- `Virtual = FALSE`

Se obtiene `InterfaceGuid` y se relaciona con `NetworkInterface.Id` de .NET.

El paquete actual del proyecto es:

`System.Management` versión `10.0.12`.

## Arquitectura actual

Navegador
    |
    | localhost
    v
ASP.NET Core MVC
    |
    v
HomeController
    |
    v
InterfazRedService
    |
    v
NetworkInterface
    |
    +--> detección de interfaz física según SO
    +--> IPv4
    +--> MAC
    +--> tipo
    |
    v
List<InterfazRed>
    |
    v
Vista Razor

La interfaz web y la lógica de descubrimiento deben mantenerse separadas para poder ampliar el proyecto posteriormente.

## Entorno actual

- Debian 13 para desarrollo y pruebas.
- .NET 10.
- ASP.NET Core MVC.
- Visual Studio Code mediante SSH.
- Git y GitHub.
- Docker disponible en el laboratorio.
- Tailscale disponible en el laboratorio.

Repositorio:

https://github.com/Frank9897/ProyectoRed.git

## Estructura actual

ProyectoRed/
|
|-- ProyectoRed.slnx
|-- README.md
|-- .gitignore
|-- docs/
|   +-- PROMPT_CONTINUIDAD.md
|-- pruebas/
+-- src/
    +-- ProyectoRed.Web/
        |-- Controllers/
        |-- Models/
        |-- Services/
        |-- Views/
        |-- wwwroot/
        |-- Program.cs
        +-- ProyectoRed.Web.csproj

## Estado actual

Ya se encuentran implementados:

- Solución `ProyectoRed.slnx`.
- Proyecto ASP.NET Core MVC.
- Configuración en .NET 10.
- Ejecución local mediante localhost.
- Página inicial personalizada.
- Modelo `Models/InterfazRed.cs`.
- Servicio `Services/InterfazRedService.cs`.
- Registro del servicio mediante inyección de dependencias.
- Inyección de `InterfazRedService` en `HomeController`.
- Lectura de interfaces mediante `NetworkInterface.GetAllNetworkInterfaces()`.
- Filtro por estado operativo `Up`.
- Filtro por tipo `Ethernet`.
- Detección adicional de interfaz física para Linux y Windows.
- Obtención del nombre de interfaz.
- Obtención y formateo de la dirección MAC.
- Obtención de direcciones IPv4.
- Obtención de `NetworkInterfaceType`.
- Creación de objetos `InterfazRed`.
- Paso de `List<InterfazRed>` desde el controlador a la vista.
- Vista Razor con `@model List<InterfazRed>`.
- Selector de interfaz que muestra el nombre proporcionado por el sistema operativo.
- Registro de `InterfazRedService` en `Program.cs` con `AddScoped`.
- Referencia al paquete `System.Management` en el proyecto.

### Archivos relevantes actuales

`src/ProyectoRed.Web/Services/InterfazRedService.cs`

Contiene la lógica de enumeración de interfaces y la detección específica de interfaz física para Linux y Windows.

`src/ProyectoRed.Web/Controllers/HomeController.cs`

Recibe `InterfazRedService` mediante inyección de dependencias y llama a `ObtenerInterfaces()`.

`src/ProyectoRed.Web/Program.cs`

Registra:

`builder.Services.AddScoped<InterfazRedService>();`

`src/ProyectoRed.Web/Views/Home/Index.cshtml`

Recibe:

`@model List<InterfazRed>`

y muestra las interfaces disponibles en un `select`.

## Estado de verificación de la detección física

La arquitectura y el código para Linux y Windows ya fueron implementados.

Todavía debe hacerse la verificación práctica en ambos sistemas:

1. Probar en Debian qué interfaces quedan después del nuevo filtro.
2. Comprobar que se excluyen interfaces virtuales como `docker0`, `br-...`, `veth...` y `tailscale0`.
3. Probar posteriormente en Windows con adaptadores Ethernet físicos y adaptadores virtuales.
4. Ajustar la implementación únicamente si las pruebas reales muestran casos que el enfoque actual no cubre.

No agregar una propiedad como “confianza física” al modelo. La identificación de interfaz física debe resolverse internamente en el servicio.

## Próximo paso inmediato

Primero verificar el comportamiento actual de `InterfazRedService.ObtenerInterfaces()` en Debian.

La meta de esta etapa es confirmar que el selector de la página muestre únicamente las interfaces Ethernet físicas relevantes.

Una vez verificado Linux, realizar la prueba en Windows.

Después de confirmar la selección de interfaz física, recién continuar con la selección de la interfaz para la etapa de descubrimiento.

## Captura Ethernet

Cuando la interfaz física esté identificada:

UTP
|
v
PC / Laptop
|
v
Interfaz Ethernet física
|
v
Captura Ethernet
|
+--> ARP
+--> LLDP
|
v
IP + MAC + Nombre

En Windows se prevé utilizar Npcap.

Para la captura y análisis de paquetes se prevé estudiar SharpPcap y PacketDotNet.

No implementar Npcap, SharpPcap ni PacketDotNet antes de que corresponda en el avance.

## Alcance de la primera versión

La primera versión debe limitarse a:

IP + MAC + Nombre

No incorporar todavía:

- escaneo completo de redes;
- descubrimiento masivo de subredes;
- detección de puertos;
- sistema operativo;
- SNMP;
- inventario avanzado;
- base de datos;
- historial;
- topología;
- mapas.

## Evolución futura

V1 — IP + MAC + Nombre
V2 — Mejoras de descubrimiento
V3 — SNMP / información de administración
V4 — LLDP y vecinos
V5 — Relaciones entre dispositivos
V6 — Descubrimiento de topología
V7 — Mapa visual de red

## Forma de desarrollo

El proyecto tiene un objetivo educativo. Se está construyendo como práctica de C#, ASP.NET Core y redes.

La metodología debe ser:

1. Explicar el objetivo del paso actual.
2. Explicar solamente los conceptos necesarios.
3. Dar pistas para que el estudiante escriba el código.
4. Esperar el intento del estudiante.
5. Revisar el código.
6. Corregir errores y explicar el motivo.
7. Mostrar una posible versión corregida después del intento.

Avanzar paso a paso y archivo por archivo, pero sin ir innecesariamente lento. Cuando una parte sea sencilla o ya haya sido explicada, se pueden agrupar varios pequeños cambios relacionados dentro del mismo paso.

No crear de golpe múltiples servicios, modelos o capas si todavía no son necesarios.

Cuando aparezca Razor/CSHTML y el estudiante no conozca el concepto, explicar primero lo básico antes de pedirle código.

El objetivo es que el estudiante escriba y entienda el código, no que simplemente copie fragmentos completos.

## Convenciones de código

Preferir nombres en español para variables, clases y métodos cuando sea razonable.

Ejemplos:

DispositivoRed
InterfazRed
ServicioDescubrimiento
CapturadorPaquetes
direccionIp
direccionMac
nombreEquipo
interfazSeleccionada
dispositivoDetectado
paqueteRecibido

Los comentarios y la documentación deben estar en español.

No cambiar estos criterios sin una razón técnica clara.

