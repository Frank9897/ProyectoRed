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

## Arquitectura prevista

~~~text
Navegador
    |
    | localhost
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

- System.Net.NetworkInformation.
- Captura de paquetes Ethernet.
- Npcap en Windows.
- SharpPcap.
- PacketDotNet.
- ARP.
- LLDP.

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
- Selector inicial de interfaz de red.
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
