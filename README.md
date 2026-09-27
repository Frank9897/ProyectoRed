# ProyectoRed

## Descripción

ProyectoRed es una aplicación web local orientada al soporte y diagnóstico de infraestructura de red.

Su objetivo inicial es permitir que un técnico conecte físicamente una PC o laptop mediante un cable UTP a un dispositivo cuya dirección IP se desconoce y obtener, cuando la información esté disponible:

- Dirección IP.
- Dirección MAC.
- Nombre del equipo.

El proyecto **no busca inicialmente escanear una red completa** ni descubrir todos los dispositivos de una subred. El escenario principal es una conexión física local entre la computadora utilizada por el técnico y el dispositivo que se desea identificar.

### Escenario de uso

~~~text
PC / Laptop de soporte
        |
        | Cable UTP
        v
Dispositivo desconocido
(switch, impresora IP, PC,
plotter, cámara, etc.)
~~~

ProyectoRed será una **web local mediante localhost**. La computadora de campo ejecutará la aplicación y utilizará el navegador como interfaz gráfica.

No se requiere durante el uso de campo:

- Servidor Debian.
- Internet.
- Tailscale.
- Docker.
- GitHub.

La aplicación final se publicará de forma autónoma para evitar exigir que la PC de campo tenga .NET previamente instalado.

## Primera versión

La primera versión será deliberadamente pequeña.

El resultado esperado:

~~~text
IP       10.0.1.1
MAC      AA:BB:CC:DD:EE:FF
Nombre   SWITCH-PISO-1
~~~

El nombre puede no estar disponible y la aplicación debe poder indicar esa situación.

No forman parte de esta primera versión el escaneo completo de redes, descubrimiento masivo de subredes, detección de puertos, identificación del sistema operativo, SNMP, historial, topología ni mapas de red.

## Arquitectura actual

~~~text
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
    +--> detección de interfaz física según sistema operativo
    +--> ARP / LLDP (etapa posterior)
    |
    v
IP + MAC + Nombre
~~~

La interfaz web y la lógica de descubrimiento deben mantenerse separadas para poder ampliar el proyecto posteriormente.

## Tecnologías

### Entorno actual

- Debian 13 como servidor de desarrollo y laboratorio.
- .NET 10.
- ASP.NET Core MVC.
- Visual Studio Code mediante SSH.
- Git y GitHub.
- Docker disponible en el laboratorio.
- Tailscale disponible en el laboratorio.

### Detección prevista

- `System.Net.NetworkInformation`.
- `System.Management` para la consulta de adaptadores en Windows.
- Captura de paquetes Ethernet.
- Npcap en Windows.
- SharpPcap.
- PacketDotNet.
- ARP.
- LLDP.

### Identificación de interfaz física

El servicio actual no depende de nombres como `enp2s0` o `Ethernet` para decidir si una interfaz es física.

En Linux se utiliza la relación de la interfaz con el dispositivo de hardware mediante `/sys/class/net/<interfaz>/device`.

En Windows se consulta `MSFT_NetAdapter` y se filtran adaptadores con:

- `ConnectorPresent = TRUE`.
- `HardwareInterface = TRUE`.
- `Virtual = FALSE`.

La implementación ya está presente en `InterfazRedService`.

Npcap y las bibliotecas de captura todavía no forman parte de la implementación actual. La preparación/instalación de Npcap deberá automatizarse posteriormente.

## Estructura actual

~~~text
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
~~~

## Estado actual

Ya se encuentran implementados:

- Solución ProyectoRed.slnx.
- Proyecto ASP.NET Core MVC.
- Configuración en .NET 10.
- Ejecución local mediante localhost.
- Página inicial personalizada.
- Modelo `InterfazRed` con nombre, IPv4, MAC y tipo.
- Servicio `InterfazRedService`.
- Lectura de interfaces mediante `NetworkInterface.GetAllNetworkInterfaces()`.
- Obtención del nombre de interfaz.
- Obtención y formateo de la dirección MAC.
- Obtención de direcciones IPv4.
- Obtención de `NetworkInterfaceType`.
- Filtro por `OperationalStatus.Up`.
- Filtro por `NetworkInterfaceType.Ethernet`.
- Detección adicional de interfaz física para Linux y Windows.
- Registro de `InterfazRedService` mediante inyección de dependencias.
- Paso de una colección `List<InterfazRed>` desde el controlador a una vista Razor.
- Vista `Index.cshtml` adaptada al modelo `InterfazRed`.
- Selector inicial de interfaz que muestra el nombre de la interfaz.
- Referencia al paquete `System.Management` versión `10.0.12`.

### Verificación pendiente

La implementación de detección física ya está escrita, pero debe verificarse con pruebas reales en:

- Debian, para comprobar qué interfaces físicas quedan y que se excluyan virtuales como Docker, bridges, veth y Tailscale.
- Windows, para comprobar el comportamiento con adaptadores Ethernet físicos y virtuales.

No se debe añadir una propiedad de “confianza física” al modelo. La decisión se realiza internamente en el servicio.

## Evolución futura

~~~text
V1  IP + MAC + Nombre
 |
 v
V2  Mejoras de descubrimiento
 |
 v
V3  SNMP / información de administración
 |
 v
V4  LLDP y vecinos
 |
 v
V5  Relaciones entre dispositivos
 |
 v
V6  Descubrimiento de topología
 |
 v
V7  Mapa visual de red
~~~

## Próximo paso

Verificar en Debian el resultado real de la detección de interfaces físicas.

Después realizar la prueba equivalente en Windows.

Cuando la selección de la interfaz física esté confirmada, avanzar a la etapa de descubrimiento mediante captura Ethernet. No implementar todavía Npcap, SharpPcap ni PacketDotNet.

## Forma de desarrollo

El proyecto tiene también un objetivo educativo. Se está construyendo como práctica de C#, ASP.NET Core y redes.

La metodología acordada es:

1. Avanzar paso a paso.
2. Trabajar archivo por archivo.
3. Explicar primero el concepto necesario.
4. El estudiante escribe el código.
5. Después se revisa y corrige el código.
6. Mantener nombres de variables, clases y métodos en español cuando sea razonable.
7. Mantener comentarios y documentación en español.
8. No adelantar componentes que todavía no sean necesarios.

La prioridad es que el código sea comprendido y no solamente copiado.

## Continuidad

El contexto completo para retomar la tutoría y las decisiones técnicas del proyecto se encuentra en:

[docs/PROMPT_CONTINUIDAD.md](docs/PROMPT_CONTINUIDAD.md)
