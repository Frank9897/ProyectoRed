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

## Funcionamiento

La aplicación será una **web local mediante localhost**. La computadora de campo ejecutará la aplicación y utilizará el navegador únicamente como interfaz gráfica.

No se requiere durante el uso de campo:

- Servidor Debian.
- Internet.
- Tailscale.
- Docker.
- GitHub.

La aplicación final se publicará de forma autónoma para evitar exigir que la PC de campo tenga .NET previamente instalado.

## Primera versión

La interfaz inicial será deliberadamente sencilla:

~~~text
+---------------------------------------------+
|                 PROYECTO RED                |
+---------------------------------------------+
|                                             |
|  Identificador de dispositivos de red       |
|                                             |
|  Interfaz de red                            |
|  [ Seleccione una interfaz...        v ]    |
|                                             |
|              [ Comenzar ]                  |
|                                             |
|  Estado: Esperando                          |
|                                             |
+---------------------------------------------+
~~~

El resultado esperado:

~~~text
IP       10.0.1.1
MAC      AA:BB:CC:DD:EE:FF
Nombre   SWITCH-PISO-1
~~~

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

- System.Net.NetworkInformation.
- Captura de paquetes Ethernet.
- Npcap en Windows.
- SharpPcap.
- PacketDotNet.
- ARP.
- LLDP.

Npcap y las bibliotecas de captura todavía no forman parte de la implementación actual. La instalación/preparación de Npcap deberá automatizarse más adelante.

## Arquitectura prevista

~~~text
Navegador
    |
    v
ASP.NET Core MVC
    |
    v
Lógica de detección
    |
    v
Interfaz Ethernet física
    |
    v
Captura / análisis
    |
    +--> ARP
    +--> LLDP
    |
    v
IP + MAC + Nombre
~~~

La interfaz web y la lógica de descubrimiento deben mantenerse desacopladas para permitir futuras ampliaciones.

## Estructura actual

~~~text
ProyectoRed/
|
|-- ProyectoRed.slnx
|-- README.md
|-- .gitignore
|-- docs/
|-- pruebas/
+-- src/
    +-- ProyectoRed.Web/
        |-- Controllers/
        |-- Models/
        |-- Views/
        |-- wwwroot/
        |-- Program.cs
        +-- ProyectoRed.Web.csproj
~~~

## Estado actual

Ya se encuentran implementados y probados:

- Solución ProyectoRed.slnx.
- Proyecto ASP.NET Core MVC.
- Configuración en .NET 10.
- Ejecución local mediante localhost.
- Página inicial personalizada.
- Selector de interfaz de red.
- Lectura de interfaces mediante NetworkInterface.GetAllNetworkInterfaces().
- Obtención del nombre de interfaz.
- Obtención de la descripción.
- Obtención del estado.
- Obtención de NetworkInterfaceType.
- Obtención y formateo de la dirección MAC.
- Obtención de direcciones IPv4.
- Paso de una colección desde el controlador a una vista Razor.
- Recorrido de la colección en CSHTML mediante @foreach.

## Problema técnico actual

Las pruebas en Debian mostraron que NetworkInterfaceType.Ethernet por sí solo no distingue siempre una interfaz Ethernet física de interfaces virtuales de Docker u otros componentes.

Se observaron interfaces como:

~~~text
lo
enp2s0
tailscale0
docker0
br-...
veth...
~~~

Por lo tanto, todavía debemos resolver de forma portable cómo identificar la interfaz Ethernet física que debe utilizar ProyectoRed.

## Fuera del alcance inicial

- Escaneo completo de redes.
- Descubrimiento de todas las subredes.
- Detección de puertos.
- Identificación del sistema operativo.
- SNMP.
- Historial.
- Topología.
- Mapas de red.

Estas funciones quedan para etapas futuras.

## Evolución prevista

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

## Forma de desarrollo

El proyecto tiene además un objetivo educativo. Se está construyendo como práctica de C#, ASP.NET Core y redes.

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

## Continuidad del proyecto

Al retomar el proyecto, conservar estas decisiones:

- Aplicación web local mediante localhost.
- La computadora de campo es la que tiene conectado físicamente el UTP.
- La primera función es identificar IP, MAC y nombre.
- No realizar todavía un escaneo completo de redes.
- Usar solamente la interfaz Ethernet física para la detección.
- Mantener el desarrollo en .NET 10.
- Automatizar Npcap más adelante.
- Continuar el desarrollo paso a paso y archivo por archivo.
