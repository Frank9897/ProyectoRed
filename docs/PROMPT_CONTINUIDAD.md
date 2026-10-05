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

El núcleo de descubrimiento identifica, cuando sea posible:

- IP.
- MAC.
- Fabricante mediante OUI.
- Nombre del equipo cuando un protocolo de descubrimiento lo aporta.

Después de una IPv4 detectada, ProyectoRed puede comprobar exclusivamente esa IP para conocer los métodos de administración disponibles.

El escenario de uso sigue siendo una conexión Ethernet local. La detección automática utiliza LLDP/CDP/EDP/FDP/NDP/HPSW/STP y ARP con las heurísticas documentadas en el servicio de captura. Después de obtener una IPv4, el servicio de acceso comprueba exclusivamente esa IP para detectar HTTP, HTTPS, SSH y Telnet. No se realiza un escaneo de puertos de la red completa.

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
    +--> búsqueda automática
    +--> búsqueda por IP
    +--> búsqueda por MAC
    +--> reutilización de MAC histórica
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

## Optimizaciones acordadas

La optimización se realiza sin cambiar la estrategia de fiabilidad del descubrimiento:

- Caché en memoria de MAC ya normalizadas durante cada detección.
- Caché en memoria de fabricante/OUI para evitar reprocesar MAC repetidas.
- No modificar por ahora rangos ARP, búsqueda 169.254/16, redes de respaldo, rondas, timeouts ni heurística.
- En búsqueda por MAC no asumir que la primera IPv4 encontrada es la correcta. Una misma MAC puede aparecer asociada a varias IPv4; esas candidatas deben conservarse para la selección por evidencia/probabilidad.

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
- Servicio Services/AccesoDispositivoService.cs para comprobar acceso y detectar métodos de administración del dispositivo.
- Modelo Models/MetodoAccesoDispositivo.cs para representar cada acceso detectado.
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
- Búsqueda Link-Local 169.254/16 como fase ampliada y concurrente con el sondeo local.
- Transmisión ARP optimizada mediante SendQueue de SharpPcap en Windows cuando Npcap expone la cola nativa.
- Repetición de solicitudes ARP y consolidación de respuestas para reducir falsos positivos.
- Análisis de solicitudes y respuestas ARP como señales adicionales.
- Puntuación heurística para seleccionar el candidato más probable cuando no existe un protocolo de vecino directo.
- Recuperación del fabricante a partir del prefijo MAC (OUI) cuando está disponible.
- Uso de historial previo de IP/MAC de la misma interfaz como señal adicional de baja latencia.
- Si no se puede confirmar una IPv4, la interfaz conserva la MAC/fabricante observados o muestra un cartel explícito de fallo; no presenta un resultado vacío como si fuera una detección exitosa.
- Detección de IPv4 desde tráfico dirigido a la PC solamente cuando la asociación es útil para el diagnóstico.
- Indicadores de tiempo transcurrido, estimación y cantidad de sondas ARP.
- Detección automática de HTTP, HTTPS, SSH y Telnet sobre la única IPv4 descubierta.
- Modelo MetodoAccesoDispositivo con puerto, protocolo, URL o comando de acceso.
- Comprobaciones de servicios ejecutadas en paralelo.
- Acciones por método para abrir una URL web confirmada o copiar comandos SSH/Telnet.
- Correspondencia entre la interfaz de .NET y el dispositivo de captura de SharpPcap mediante GUID en Windows.
- Captura pasiva de MAC e IPv4 del dispositivo remoto cuando aparece tráfico Ethernet/ARP/IPv4.
- Endpoint de descubrimiento desde HomeController.
- Botón Comenzar conectado a la detección desde la interfaz web.
- Modos de búsqueda en la interfaz: automática, por IP y por MAC.
- Normalización y validación de MAC para búsquedas directas.
- Búsqueda por MAC filtrando las evidencias ARP y de descubrimiento por la MAC objetivo.
- Uso de los rangos de respaldo existentes también cuando se conoce la MAC.
- Reutilización del historial: una IP histórica puede aportar su MAC para buscar la IPv4 actual.
- Fallback a ARP dirigido sobre la IP original si la MAC recuperada del historial ya no responde.
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

### Modos de búsqueda

La interfaz de ProyectoRed permite seleccionar uno de tres criterios:

~~~text
Automática
Por IP
Por MAC
~~~

#### Automática

Cuando no se conoce ninguna identidad concreta, se mantiene el flujo actual:

~~~text
LLDP / CDP / EDP / FDP / NDP / HPSW / STP
                    ↓
              captura pasiva
                    ↓
             sondeo ARP
                    ↓
       consolidación y heurística
~~~

La búsqueda ARP puede recorrer la subred local, Link-Local 169.254/16 y rangos de respaldo según las condiciones ya implementadas. El resultado heurístico sigue diferenciándose de una confirmación por vecino directo.

#### Por IP

Cuando el técnico conoce la IPv4 del dispositivo, ProyectoRed realiza una consulta ARP dirigida a esa única IP para obtener la MAC actual y los demás datos asociados disponibles.

Antes de iniciar el flujo de descubrimiento, el historial de la interfaz seleccionada se consulta por esa IP. Si existe un registro, se recupera **solo la MAC** y se utiliza como identidad para buscar su IPv4 actual. La IP guardada no se considera permanente.

Si la búsqueda por la MAC histórica no encuentra el equipo, se realiza un fallback mediante ARP dirigido a la IP solicitada. Esto permite seguir funcionando aunque la MAC haya cambiado.

#### Por MAC

Cuando el técnico conoce la MAC del chasis o etiqueta del equipo, puede introducir:

~~~text
AA:BB:CC:DD:EE:FF
AA-BB-CC-DD-EE-FF
AABBCCDDEEFF
~~~

ProyectoRed normaliza la dirección y solamente considera coincidencias que correspondan exactamente con esa MAC.

El flujo es:

~~~text
MAC conocida
     ↓
LLDP / CDP / EDP / FDP / NDP / HPSW / STP
     ↓
ARP
     ↓
¿MAC observada == MAC buscada?
     ↓
     Sí
     ↓
IPv4 + MAC + nombre + fabricante
~~~

Cuando la MAC es conocida, ya no es necesario escoger entre varios candidatos mediante la puntuación heurística: una respuesta con la misma MAC establece directamente el vínculo IP/MAC.

La búsqueda por MAC utiliza también los rangos de respaldo existentes para cubrir el escenario en el que la IP fija del dispositivo se encuentra fuera de la subred actualmente configurada en la PC.

## Tecnologías legacy agregadas para localizar al vecino

La detección mantiene LLDP como estándar principal y suma tecnologías históricas de descubrimiento de capa 2 para ampliar la cobertura de equipos antiguos.

### NDP / HGMPv2

Los switches H3C documentan NDP como un protocolo para descubrir vecinos directamente conectados. En HGMPv2, H3C documenta 01:80:C2:00:00:0A como dirección multicast predeterminada y permite otras direcciones del rango 01:80:C2:00:00:20-2F.

ProyectoRed usa estas tramas como señal adicional de vecino local. Por seguridad, el parser agregado no inventa un formato interno para NDP que no esté suficientemente respaldado: conserva la MAC de origen y deja que el ARP posterior, ya restringido a esa MAC, complete la IPv4 cuando sea posible.

### HPSW

Se agregó reconocimiento del HP Switch Protocol sobre HP Extended LLC. Cuando la trama contiene los TLV conocidos, ProyectoRed puede obtener:

- nombre del dispositivo;
- IPv4;
- MAC propia del dispositivo.

HPSW queda como ruta legacy complementaria y no reemplaza LLDP/CDP.

### Dell ISDP

ISDP de Dell utiliza compatibilidad con CDP. La ruta CDP existente ya interpreta ese formato de trama, por lo que ISDP queda cubierto sin duplicar el parser.

## Acceso y métodos de administración del dispositivo

Cuando ProyectoRed obtiene una IPv4 del dispositivo, puede comprobar automáticamente los servicios de administración sobre esa única dirección.

Se prueban:

~~~text
HTTP    TCP 80
HTTPS   TCP 443
HTTP    TCP 8080
HTTPS   TCP 8443
SSH     TCP 22
Telnet  TCP 23
~~~

Las pruebas de servicios se ejecutan en paralelo. HTTP y HTTPS se validan mediante una petición de solo lectura después de establecer la conexión; HTTPS realiza handshake TLS sin utilizar el certificado para decidir confianza. SSH se valida mediante su banner inicial. Telnet se considera disponible cuando TCP/23 acepta la conexión.

El resultado se almacena en EstadoAccesoDispositivo.MetodosAcceso y la vista muestra solamente los métodos que respondieron.

Cada servicio detectado muestra su propia acción. Para HTTP/HTTPS se ofrece una URL realmente comprobada; para SSH y Telnet se muestra una acción para copiar el comando:

~~~text
ssh IP
telnet IP 23
~~~

La comprobación nunca recorre otras direcciones y no intenta autenticarse en el equipo.

La comparación de subred continúa siendo:

~~~text
(IPPC AND MascaraPC) == (IPDispositivo AND MascaraPC)
~~~

Cuando las redes no coinciden, no se presentan los servicios como accesibles directamente y se conserva la guía de configuración IPv4 temporal.

No se modifican automáticamente las configuraciones de red de Windows ni la configuración del switch.

## Próximo paso inmediato

La búsqueda automática, la búsqueda por IP, la búsqueda por MAC y la reutilización del historial ya están incorporadas.

La siguiente validación debe comprobar con hardware real:

~~~text
1. IP conocida → MAC actual.
2. MAC conocida → IP actual.
3. Sin IP/MAC → descubrimiento automático y heurística.
4. IP histórica → MAC histórica → búsqueda de IPv4 actual.
5. MAC histórica obsoleta → fallback a la IP original.
~~~

Las pruebas deben incluir dispositivos con IP fija, con y sin puerta de enlace, PC con DHCP y equipos cuya IP esté en otra red. La prioridad es comprobar precisión y evitar que una heurística ARP sea presentada como una identificación física confirmada.

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
