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

El escenario de uso sigue siendo una conexión Ethernet local. La detección automática utiliza la máscara de la interfaz seleccionada para realizar un sondeo ARP de la subred cuando es posible, además de LLDP/CDP, tráfico IPv4/ARP y rangos de respaldo. No se realiza detección de puertos ni inventario de servicios.

## Funcionamiento en campo

La aplicación debe funcionar localmente y no depender de:

- servidor Debian;
- Internet;
- Tailscale;
- Docker;
- GitHub;
- .NET instalado previamente en la PC de campo.

El servidor Debian se utiliza para desarrollar y probar el proyecto.

La aplicación terminada debe publicarse para Windows x64 como **self-contained** y **single-file**, de modo que incluya el runtime de .NET y las dependencias administradas. El ejecutable inicia el servidor web local en http://127.0.0.1:5094 y abre el navegador predeterminado en Windows.

La configuración de publicación se encuentra en:

src/ProyectoRed.Web/Properties/PublishProfiles/WindowsSelfContained.pubxml

El procedimiento está documentado en:

docs/DEPLOYMENT_WINDOWS.md

### Dependencia Npcap

La captura Ethernet en Windows requiere Npcap.

Npcap es un controlador/componente del sistema, no una biblioteca de .NET. Por tanto, una publicación self-contained de .NET no elimina esta dependencia del sistema.

La edición gratuita de Npcap no permite redistribución externa; para distribuir Npcap junto con ProyectoRed se requiere la licencia correspondiente de Npcap OEM.

## Detección de interfaz Ethernet

La aplicación debe trabajar con la interfaz Ethernet física utilizada para la conexión UTP.

No se debe seleccionar una interfaz física mediante nombres concretos como enp2s0, Ethernet o similares, porque esos nombres pueden cambiar entre sistemas y equipos.

Tampoco se debe convertir el proyecto en un scanner de Wi-Fi, Tailscale, Docker, loopback ni otras interfaces virtuales.

### Enfoque implementado

System.Net.NetworkInformation se utiliza para enumerar las interfaces disponibles.

El servicio InterfazRedService mantiene los filtros generales:

- OperationalStatus.Up
- NetworkInterfaceType.Ethernet

Además, incorpora una comprobación específica por sistema operativo para descartar interfaces virtuales.

### Linux

En Linux se comprueba la ruta:

/sys/class/net/<nombre>/device

y se utiliza el vínculo hacia el dispositivo para distinguir una interfaz asociada a hardware de interfaces virtuales.

No se depende de prefijos como enp, eth o nombres similares.

### Windows

En Windows se consulta MSFT_NetAdapter mediante System.Management, utilizando:

- ConnectorPresent = TRUE
- HardwareInterface = TRUE
- Virtual = FALSE

Se obtiene InterfaceGuid y se relaciona con NetworkInterface.Id de .NET.

El paquete actual del proyecto es:

System.Management versión 10.0.12.

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
    +--> detección de interfaz física según SO
    +--> IPv4
    +--> MAC
    +--> tipo
    |
    v
CapturadorPaquetesService
    |
    +--> SharpPcap
    +--> PacketDotNet
    +--> Ethernet
    +--> LLDP
    |
    v
IP + MAC + Nombre

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
|   +-- DEPLOYMENT_WINDOWS.md
|-- publicar-windows.bat
+-- src/
    +-- ProyectoRed.Web/
        |-- Controllers/
        |-- Models/
        |-- Services/
        |-- Views/
        |-- wwwroot/
        |-- Program.cs
        |-- ProyectoRed.Web.csproj
        +-- Properties/
            +-- PublishProfiles/
                +-- WindowsSelfContained.pubxml

## Estado actual

Ya se encuentran implementados:

- Solución ProyectoRed.slnx.
- Proyecto ASP.NET Core MVC.
- Configuración en .NET 10.
- Servidor HTTP local en 127.0.0.1:5094.
- Apertura automática del navegador en Windows.
- Página inicial personalizada.
- Modelo Models/InterfazRed.cs.
- Servicio Services/InterfazRedService.cs.
- Servicio Services/AccesoDispositivoService.cs para validar acceso a la interfaz del dispositivo.
- Registro del servicio mediante inyección de dependencias.
- Lectura de interfaces mediante NetworkInterface.GetAllNetworkInterfaces().
- Filtro por estado operativo Up.
- Filtro por tipo Ethernet.
- Detección adicional de interfaz física para Linux y Windows.
- Clasificación básica de IPv4 mediante ClasificadorDireccionService, sin modificar el modelo DispositivoDetectado.
- Obtención del nombre de interfaz.
- Obtención y formateo de la dirección MAC.
- Obtención de direcciones IPv4.
- Obtención de NetworkInterfaceType.
- Creación de objetos InterfazRed.
- Paso de List<InterfazRed> desde el controlador a la vista.
- Vista Razor con @model List<InterfazRed>.
- Selector de interfaz que muestra el nombre proporcionado por el sistema operativo.
- Referencia al paquete System.Management versión 10.0.12.
- Referencias a SharpPcap 6.3.1 y PacketDotNet 1.4.8.
- Servicio CapturadorPaquetesService.
- Captura limitada a unos segundos para evitar loops de salida.
- Análisis Ethernet mediante PacketDotNet.
- Detección de paquetes LLDP.
- Lectura del System Name de LLDP cuando está presente.
- Lectura del Management Address TLV IPv4 de LLDP.
- Detección de CDP.
- Lectura de Device-ID y Address TLV IPv4 de CDP.
- Detección de STP/RSTP como señal de vecino de capa 2.
- Detección de EDP de Extreme Networks.
- Lectura de Display y VLAN IP de EDP.
- Sondeo ARP automático de la subred local.
- Búsqueda Link-Local 169.254/16 como fase ampliada y paralela al sondeo ARP local.
- Repetición de solicitudes ARP y consolidación de respuestas para reducir falsos positivos.
- Detección de IPv4 desde tráfico dirigido a la PC solamente cuando la asociación es útil para el diagnóstico.
- Indicadores de tiempo transcurrido, estimación y cantidad de sondas ARP.
- Correspondencia entre la interfaz de .NET y el dispositivo de captura de SharpPcap mediante GUID en Windows.
- Captura pasiva de MAC e IPv4 del dispositivo remoto cuando aparece tráfico Ethernet/ARP/IPv4.
- Endpoint de descubrimiento desde HomeController.
- Botón Comenzar conectado a la detección desde la interfaz web.
- Botón para abrir la interfaz web del dispositivo detectado.
- Endpoint Home/AccesoDispositivo.
- Comparación de red IPv4 mediante IP y máscara.
- Consulta de si la interfaz utiliza DHCP.
- Generación de una sugerencia temporal de configuración IPv4 manual.
- Perfil de publicación Windows x64 self-contained + single-file.
- Script publicar-windows.bat.

## Estado de verificación de captura y despliegue

En Debian ya se comprobó que:

1. SharpPcap enumera las interfaces.
2. La interfaz Ethernet física puede abrirse con permisos adecuados.
3. La captura Ethernet funciona.
4. PacketDotNet puede interpretar paquetes Ethernet.
5. Durante una prueba limitada de 5 segundos no apareció LLDP.

En Windows además se comprobó que:

1. Npcap está correctamente instalado.
2. SharpPcap puede abrir el adaptador físico.
3. `Ethernet 2` de .NET se relaciona correctamente con `\\Device\\NPF_{GUID}` mediante `NetworkInterface.Id`.
4. La aplicación publicada self-contained + single-file puede ejecutarse sin instalar .NET previamente.
5. El servidor local funciona mediante `http://127.0.0.1:5094`.

La ausencia de LLDP no implica que el capturador esté roto.

También se comprobó que tomar el primer ARP observado como si fuera el dispositivo objetivo es incorrecto: el tráfico ARP capturado puede corresponder a otros equipos de la red.

## Despliegue Windows

El objetivo de despliegue es:

~~~text
PC de campo
    |
    +--> ProyectoRed.Web.exe
    |       |
    |       +--> runtime .NET incluido
    |       +--> dependencias administradas incluidas
    |       +--> servidor localhost
    |       +--> navegador
    |
    +--> Npcap
           |
           +--> controlador necesario para captura Ethernet
~~~

No copiar una instalación de dotnet a la PC de campo como requisito separado.

La publicación self-contained es específica de plataforma; actualmente se prepara para win-x64. Para otra arquitectura se debe crear una publicación distinta.

## Alcance de la primera versión

La primera versión debe limitarse a:

IP + MAC + Nombre

La detección automática puede realizar un sondeo ARP acotado a la interfaz seleccionada, además de LLDP/CDP y captura pasiva. No se incorporan detección de puertos, sistema operativo, SNMP, inventario avanzado, topología ni mapas.

## Clasificación básica de IPv4

La clasificación de la dirección se agregó como lógica independiente y no modifica el modelo DispositivoDetectado.

El servicio ClasificadorDireccionService recibe una IPv4 y devuelve una descripción:

~~~text
IPv4 privada
IPv4 Link-Local
IPv4 pública/global
IPv4 de loopback
IPv4 multicast
IPv4 no especificada
~~~

Ejemplos:

~~~text
10.0.1.1       -> IPv4 privada
192.168.0.1    -> IPv4 privada
169.254.10.20  -> IPv4 Link-Local
8.8.8.8        -> IPv4 pública/global
127.0.0.1      -> IPv4 de loopback
224.0.0.1      -> IPv4 multicast
0.0.0.0        -> IPv4 no especificada
~~~

El objetivo es informar al técnico sin convertir la clasificación en un dato permanente del modelo principal.

## Descubrimiento sin puerta de enlace

La puerta de enlace IPv4 es opcional para el capturador. Ya no es la condición que determina si la detección automática puede empezar.

Con IPv4 + máscara:
- se sondea primero la puerta de enlace si existe;
- se prueban las direcciones utilizables de la subred local;
- la búsqueda se detiene al obtener una IPv4.

Sin gateway pero con IPv4:
- el comportamiento es el mismo; el gateway ya no es necesario.

Sin IPv4 local:
- LLDP/CDP y captura pasiva siguen disponibles;
- las sondas ARP manuales y automáticas utilizan 0.0.0.0 como dirección de origen cuando corresponde;
- también se buscan rangos habituales, incluyendo 169.254.0.0/16.

La captura se abre en modo promiscuo para maximizar la visibilidad de las tramas Ethernet útiles para LLDP/CDP y diagnóstico de capa 2. La asociación final de una IP con el dispositivo sigue estando restringida por MAC, IP objetivo y/o destino de la trama.

### Detección manual

La interfaz de ProyectoRed ofrece un único campo:

- IP del dispositivo.

La **IP del dispositivo** permite hacer una consulta ARP puntual contra una única dirección conocida.

No se solicita una IP local de prueba. Si la PC tiene una IPv4 se usa automáticamente como origen; si no tiene IPv4, la sonda ARP puede utilizar 0.0.0.0 sin modificar la configuración de Windows.

Cuando no se conoce la IP del dispositivo, la aplicación utiliza la detección automática: LLDP, CDP, tráfico IPv4, ARP pasivo, sondeo ARP de la subred local y rangos de respaldo.

La interfaz también diferencia el estado del enlace del resultado de identificación:

~~~text
Enlace UTP activo
    +
IP/MAC/Nombre identificado

o

Enlace UTP activo
    +
sin identidad obtenida
~~~

Por lo tanto, la ausencia de IP/MAC ya no debe interpretarse automáticamente como ausencia física del dispositivo.

## Acceso a la interfaz del dispositivo

Cuando el resultado de descubrimiento contiene una IPv4, la vista permite intentar abrir la interfaz web del dispositivo.

El flujo es:

~~~text
Vista
 |
 | GET /Home/AccesoDispositivo
 v
HomeController
 |
 v
AccesoDispositivoService
 |
 +--> obtiene IPv4 y máscara de la interfaz seleccionada
 +--> consulta si DHCP está habilitado
 +--> compara la red de la PC con la red del dispositivo
 |
 +--> misma red: permite abrir http://IP
 |
 +--> red diferente: informa la situación y muestra
      una configuración IPv4 manual temporal
~~~

La comparación se realiza mediante:

~~~text
(IPPC AND Mascara) == (IPDispositivo AND Mascara)
~~~

No se cambia automáticamente la configuración de red del sistema.

Cuando el acceso web no puede confirmarse con la configuración actual, se propone una configuración temporal de prueba basada en una IP adyacente a la IP detectada y máscara /24. La máscara real del dispositivo no se conoce todavía; la sugerencia no pretende afirmarla como definitiva.

Antes de ofrecer la guía, el servicio prueba los puertos web habituales 443, 80, 8443 y 8080 y, cuando encuentra uno abierto, genera la URL correspondiente.

La puerta de enlace queda vacía porque el objetivo es acceder localmente al dispositivo.

## Próximo paso inmediato

La publicación Windows y la captura con Npcap ya fueron verificadas.

La siguiente etapa es validar la detección automática con dispositivos de IP fija en subredes típicas, con y sin puerta de enlace, comprobando especialmente el caso en que Windows obtiene una IPv4 por DHCP y el equipo remoto mantiene una IP fija.

La captura actual trabaja durante unos segundos y recopila, cuando existen:

- MAC remota desde Ethernet.
- IPv4 desde ARP o IPv4, asociada a la MAC que originó ese mismo tráfico.
- Nombre desde LLDP System Name, asociado a la misma MAC.

No se debe tomar el primer paquete ARP de una red compartida como identificación automática del dispositivo.

La estrategia automática usa la máscara real de la interfaz cuando existe para construir la subred local. El sondeo de esa red y el sondeo Link-Local 169.254/16 se ejecutan concurrentemente después de la fase inicial de protocolos de capa 2. La configuración temporal de acceso es distinta: propone /24 como primera prueba junto con una IP adyacente a la IP detectada.

## Forma de desarrollo

El proyecto tiene un objetivo educativo. Se está construyendo como práctica de C#, ASP.NET Core y redes.

La metodología debe ser:

1. Explicar el objetivo del paso actual.
2. Explicar solamente los conceptos necesarios.
3. Avanzar paso a paso, pero sin ir innecesariamente lento.
4. Mantener nombres de variables, clases y métodos en español cuando sea razonable.
5. Mantener comentarios y documentación en español.
6. Cuando una modificación sea concreta y el usuario lo pida, realizarla directamente en el repositorio y dejar al usuario la ejecución de git pull, dotnet build y dotnet run.
7. No crear de golpe múltiples servicios, modelos o capas si todavía no son necesarios.

## Convenciones de código

Preferir nombres en español para variables, clases y métodos cuando sea razonable.

Los comentarios y la documentación deben estar en español.

No cambiar estos criterios sin una razón técnica clara.
