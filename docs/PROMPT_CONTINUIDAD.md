# Prompt de continuidad — ProyectoRed

Quiero continuar una tutoría práctica de C# y redes sobre un proyecto llamado ProyectoRed.

## Objetivo

ProyectoRed es una aplicación web local que debe ejecutarse mediante localhost en la misma PC o laptop que el técnico utiliza en el lugar donde se encuentra el dispositivo.

El escenario principal es:

PC o laptop de soporte
|
| Cable UTP
v
Dispositivo cuya IP se desconoce

El dispositivo puede ser, por ejemplo, un switch administrable, una impresora IP, un plotter, una PC, una cámara u otro dispositivo de red.

La primera versión debe ser muy sencilla. Su objetivo es identificar, cuando sea posible:

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

## Captura Ethernet

La detección debe realizarse sobre la interfaz Ethernet física utilizada para la conexión UTP.

No se debe convertir el proyecto en un scanner de Wi-Fi, Tailscale, Docker, loopback ni otras interfaces virtuales.

En Windows se prevé utilizar Npcap y automatizar su preparación o instalación cuando lleguemos a esa etapa.

Para la captura y análisis de paquetes se prevé estudiar SharpPcap y PacketDotNet.

ARP y LLDP son mecanismos especialmente relevantes para las etapas iniciales de descubrimiento.

No implementar Npcap, SharpPcap ni PacketDotNet antes de que corresponda en el avance.

## Entorno de desarrollo actual

- Debian 13.
- .NET 10.
- ASP.NET Core MVC.
- Visual Studio Code mediante SSH.
- Git y GitHub.
- Docker disponible en el servidor.
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
|-- pruebas/
+-- src/
    +-- ProyectoRed.Web/
        |-- Controllers/
        |-- Models/
        |-- Views/
        |-- wwwroot/
        |-- Program.cs
        +-- ProyectoRed.Web.csproj

## Estado actual

Ya existe un proyecto ASP.NET Core MVC en .NET 10 y se comprobó su ejecución mediante localhost.

La página inicial personalizada contiene conceptualmente:

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

Se trabajó con NetworkInterface.GetAllNetworkInterfaces() para obtener las interfaces del equipo.

Se practicó la obtención de:

- Name.
- Description.
- OperationalStatus.
- NetworkInterfaceType.
- GetPhysicalAddress().
- GetIPProperties().
- UnicastAddresses.
- AddressFamily.InterNetwork.

También se practicó la conversión de PhysicalAddress a una MAC legible utilizando GetAddressBytes(), BitConverter y Replace().

Se aprendió a pasar una colección desde un Controller hacia una vista Razor mediante return View(coleccion) y a recorrerla con @foreach.

## Aprendizaje de MVC y Razor

El estudiante no quiere recibir todo el código terminado.

La metodología debe ser:

1. Explicar el objetivo del paso actual.
2. Explicar solamente los conceptos, clases, métodos o propiedades necesarios.
3. Dar pistas para que el estudiante escriba el código.
4. Esperar el intento del estudiante.
5. Revisar el código.
6. Corregir errores y explicar el motivo.
7. Mostrar una posible versión corregida después del intento.

Avanzar paso a paso y archivo por archivo.

No crear de golpe múltiples servicios, modelos o capas si todavía no son necesarios.

Cuando aparezca Razor/CSHTML y el estudiante no conozca el concepto, explicar primero lo básico antes de pedirle código.

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

Una evolución posible es:

V1 — IP + MAC + Nombre
V2 — Mejoras de descubrimiento
V3 — SNMP / información de administración
V4 — LLDP y vecinos
V5 — Relaciones entre dispositivos
V6 — Descubrimiento de topología
V7 — Mapa visual de red

## Problema pendiente actual

Se intentó filtrar la interfaz local utilizando OperationalStatus.Up y NetworkInterfaceType.Ethernet.

Durante las pruebas en Debian se observó que Linux puede presentar interfaces virtuales creadas por Docker y otros componentes como interfaces de tipo Ethernet.

Se observaron nombres como:

lo
enp2s0
tailscale0
docker0
br-...
veth...

Por lo tanto, el problema pendiente es encontrar una manera correcta y portable de identificar la interfaz Ethernet física sin depender de nombres concretos como enp2s0.

Ese es el siguiente problema técnico a estudiar antes de pasar a la captura Ethernet.

## Objetivo técnico posterior

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

No avanzar todavía a topología ni funcionalidades avanzadas.
