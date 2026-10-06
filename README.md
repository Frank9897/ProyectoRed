# ProyectoRed

## Descripción

ProyectoRed es una aplicación web local orientada al soporte y diagnóstico de infraestructura de red.

Su objetivo es permitir que un técnico conecte físicamente una PC o laptop mediante un cable UTP a un dispositivo cuya dirección IP se desconoce y obtener, cuando la información esté disponible:

- Dirección IP.
- Dirección MAC.
- Fabricante a partir del OUI.
- Nombre del equipo cuando un protocolo de descubrimiento lo proporciona.

Una vez obtenida una IPv4, ProyectoRed comprueba exclusivamente esa dirección para determinar qué métodos de administración responden: HTTP, HTTPS, SSH y Telnet.

El escenario principal sigue siendo una conexión física local entre la computadora utilizada por el técnico y el dispositivo que se desea identificar.

La detección automática utiliza LLDP, CDP, EDP, FDP, NDP/HGMPv2, HPSW, STP y ARP activo acotado a la interfaz seleccionada. La comprobación de servicios es independiente del descubrimiento y nunca recorre otras direcciones de la red.

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
- .NET instalado previamente.

La aplicación final se publica como **self-contained para Windows x64**, incluyendo el runtime de .NET y las dependencias administradas en un ejecutable. Por tanto, la PC de campo no necesita instalar .NET por separado.

## Ejecución en campo

La aplicación se ejecuta mediante:

~~~text
ProyectoRed.Web.exe
       |
       +--> inicia servidor ASP.NET Core local
       |
       +--> http://127.0.0.1:5094
       |
       +--> abre el navegador predeterminado
~~~

La aplicación utiliza **HTTP local** para evitar depender de un certificado HTTPS de desarrollo.

La publicación actual está preparada para Windows x64 y se configura mediante:

~~~text
src/ProyectoRed.Web/Properties/PublishProfiles/
    WindowsSelfContained.pubxml
~~~

El procedimiento de publicación está documentado en:

~~~text
docs/DEPLOYMENT_WINDOWS.md
~~~

### Importante sobre captura de paquetes

El runtime de .NET sí queda incluido en la publicación self-contained.

La captura Ethernet en Windows utiliza **Npcap**, que es un componente del sistema que instala un controlador de captura. Npcap no forma parte del runtime de .NET y no se puede considerar resuelto únicamente con una publicación single-file.

La edición gratuita de Npcap no permite redistribución externa con un producto. Para incluir su instalador dentro de ProyectoRed se requiere la licencia correspondiente de Npcap OEM.

Por este motivo, la publicación de ProyectoRed resuelve la dependencia de **.NET**, mientras que la instalación de **Npcap** se tratará como una etapa separada del despliegue de campo.

## Primera versión

La primera versión será deliberadamente pequeña.

El resultado de descubrimiento puede incluir:

~~~text
IP          10.0.1.1
MAC         AA:BB:CC:DD:EE:FF
Fabricante  HPE / Aruba
Nombre      SWITCH-PISO-1
~~~

Después se muestra una sección separada con los métodos de administración detectados para esa única IP:

~~~text
HTTPS  TCP 443  [Abrir]
SSH    TCP 22   [Copiar comando]
~~~

El nombre puede no estar disponible.

La comprobación de acceso no es un escaneo de puertos de la red: solo prueba los puertos de administración configurados sobre la IPv4 que ProyectoRed ya identificó. No se intenta autenticar ni descubrir credenciales.

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
    +--> detección de interfaz física según sistema operativo
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
    +--> LLDP / CDP / EDP / FDP / NDP-HGMPv2 / HPSW / STP
    +--> ARP
    |
    v
IP + MAC + fabricante
    |
    v
AccesoDispositivoService
    |
    +--> HTTP / HTTPS
    +--> SSH
    +--> Telnet
    |
    v
Métodos de acceso disponibles
~~~

La interfaz web y la lógica de descubrimiento deben mantenerse separadas para poder ampliar el proyecto posteriormente.

## Optimizaciones actuales

La lógica de descubrimiento mantiene intacta la estrategia de fiabilidad y solo optimiza trabajo repetitivo durante la ejecución:

- Las MAC ya normalizadas se reutilizan mediante una caché en memoria durante cada detección.
- Fabricante y OUI se almacenan en caché en memoria para evitar repetir el procesamiento de las mismas MAC observadas.
- No se cambia el barrido ARP, la búsqueda Link-Local, las redes de respaldo, las rondas ni la heurística de candidatos.
- En modo MAC no se detiene la búsqueda al encontrar la primera IP: se conserva la posibilidad de observar varias IPv4 asociadas a la misma MAC y posteriormente aplicar el criterio de selección correspondiente.
- Cuando un protocolo L2 ya confirmó al vecino directo por su MAC, las respuestas ARP de esa misma MAC se conservan aunque su IPv4 quede fuera de los rangos activos del sondeo. Si aparecen varias IPv4, se selecciona la candidata con mayor evidencia.
- Si el protocolo L2 anuncia una MAC diferente de la utilizada por el equipo en ARP, las respuestas ARP no se descartan. Cuando existe coincidencia de MAC se prioriza; cuando no existe, la selección vuelve a todas las candidatas ARP para evitar perder la IPv4 del vecino.
- En LLDP, el modo MAC puede comparar la MAC Ethernet de origen y el Chassis ID cuando este usa subtipo MAC. En automático, un LLDP válido mantiene prioridad y evita iniciar el sondeo ARP, aunque el anuncio no incluya Management Address.
- En CDP, la MAC Ethernet de origen y una MAC expresada dentro del Device-ID textual pueden actuar como identidades para la búsqueda por MAC. El Device-ID de CDP no siempre es una MAC: también puede ser nombre de sistema o número de serie. Para evitar falsos positivos, el proyecto solo acepta el Device-ID como MAC cuando su texto se puede normalizar a un formato MAC válido.
- En STP/RSTP/MSTP, la búsqueda por MAC puede comparar la MAC Ethernet de origen y la MAC contenida en el Bridge Identifier de la BPDU. STP no aporta por sí mismo una IPv4 de administración, por lo que continúa con ARP cuando sea necesario.
- EDP ya utiliza el Switch ID/MAC del encabezado EDP; HPSW prioriza el Own MAC Address publicado por su TLV; FDP y NDP conservan la MAC de origen como identidad del vecino en la implementación actual.
- Cuando llegan anuncios de varios protocolos L2 durante la misma captura, ProyectoRed conserva la identidad del protocolo con mayor prioridad en lugar de reemplazarla con una señal más débil. La prioridad actual es LLDP, luego CDP/EDP, FDP/HPSW, NDP/HGMPv2 y finalmente STP. Esto evita que un BPDU posterior desplace una identidad LLDP ya establecida.

## Tecnologías

### Entorno de desarrollo

- Debian 13 como servidor de desarrollo y laboratorio.
- .NET 10.
- ASP.NET Core MVC.
- Visual Studio Code mediante SSH.
- Git y GitHub.
- Docker disponible en el laboratorio.
- Tailscale disponible en el laboratorio.

### Captura y análisis

- Npcap en Windows.
- SharpPcap.
- PacketDotNet.
- ARP.
- LLDP.

### Detección de interfaz física

- System.Net.NetworkInformation.
- System.Management para Windows.
- Linux: /sys/class/net/<interfaz>/device.
- Windows: MSFT_NetAdapter.

## Identificación de interfaz física

El servicio actual no depende de nombres como enp2s0 o Ethernet para decidir si una interfaz es física.

En Linux se utiliza la relación de la interfaz con el dispositivo de hardware mediante /sys/class/net/<interfaz>/device.

En Windows se consulta MSFT_NetAdapter y se filtran adaptadores con:

- ConnectorPresent = TRUE.
- HardwareInterface = TRUE.
- Virtual = FALSE.

La implementación ya está presente en InterfazRedService.

No se añade ninguna propiedad de “confianza física” al modelo.

## Estado actual

Ya se encuentran implementados:

- Solución ProyectoRed.slnx.
- Proyecto ASP.NET Core MVC.
- .NET 10.
- Ejecución local mediante localhost.
- Servidor HTTP local en 127.0.0.1:5094.
- Apertura automática del navegador en Windows.
- Modelo InterfazRed con nombre, IPv4, MAC y tipo.
- Servicio InterfazRedService.
- Modelo MetodoAccesoDispositivo para representar cada método de administración detectado.
- Servicio AccesoDispositivoService para detectar métodos de administración sobre la IP del dispositivo.
- Enumeración de interfaces mediante NetworkInterface.GetAllNetworkInterfaces().
- Filtro por OperationalStatus.Up.
- Filtro por NetworkInterfaceType.Ethernet.
- Detección de interfaz física específica para Linux y Windows.
- Clasificación básica de la IPv4 detectada sin agregar campos al modelo DispositivoDetectado.
- Registro mediante inyección de dependencias.
- Captura de paquetes con SharpPcap.
- Análisis Ethernet con PacketDotNet.
- Prueba de captura limitada a unos segundos para evitar ejecución indefinida.
- Detección de paquetes LLDP.
- Lectura del System Name de LLDP cuando el paquete lo proporciona.
- Publicación prevista como ejecutable Windows x64 self-contained y single-file.

### Verificación actual

En Debian y Windows ya se comprobó que:

- SharpPcap puede abrir la interfaz Ethernet física con permisos adecuados.
- En Windows, Npcap proporciona la captura necesaria y la correspondencia entre `NetworkInterface.Id` y el GUID de `\\Device\\NPF_{GUID}` funciona.
- La captura Ethernet funciona.
- PacketDotNet puede interpretar paquetes Ethernet.
- En las pruebas realizadas no apareció LLDP.

La ausencia de LLDP no implica un fallo del capturador; el dispositivo o la red de prueba puede no estar enviando anuncios LLDP.

### Descubrimiento actual

La captura ya se utiliza para obtener información del dispositivo remoto en una conexión física directa:

- La MAC y la IPv4 se toman del mismo dispositivo observado: ambas quedan asociadas por la MAC Ethernet de origen.
- La IPv4 se obtiene del emisor de ARP o de un paquete IPv4 cuando aparece.
- El nombre se obtiene del TLV System Name de LLDP y se asocia a la misma MAC cuando está presente.
- No se mezclan una MAC de un paquete con una IP de otro dispositivo.
- La captura está limitada a unos segundos para evitar loops y no ejecutarse indefinidamente.

La estrategia combina descubrimiento pasivo y activo:

- LLDP/CDP para identificar al vecino directamente conectado.
- NDP/HGMPv2 para conservar la señal de vecino local de switches H3C/3Com legacy.
- HPSW para identificar switches HP legacy que utilicen HP Extended LLC.
- Tráfico IPv4/ARP observado durante la captura.
- Sondeo ARP automático de la red IPv4 local cuando existe una IPv4 y máscara.
- Direcciones administrativas habituales cuando la PC está en otra red o todavía no tiene IPv4.
- Rango IPv4 Link-Local 169.254.0.0/16 como búsqueda adicional.

Cuando existe una IPv4 local, la máscara de la interfaz determina qué subred se puede sondear automáticamente. Para redes hasta /16 el sondeo puede recorrer los hosts utilizables. Redes mucho más grandes no se recorren completas para evitar una operación excesiva.

Una conexión Ethernet en estado UP confirma el enlace físico, pero por sí sola no proporciona la IPv4 del equipo remoto. Por eso la versión actual ya no depende únicamente de esperar tráfico espontáneo.

## Protocolos adicionales de descubrimiento de capa 2

Además de LLDP/CDP/EDP/FDP/STP, el capturador incorpora señales legacy para mejorar la localización del equipo conectado directamente por UTP.

### NDP / HGMPv2 de H3C y 3Com

Los switches H3C documentan NDP como un protocolo de capa 2 para descubrir vecinos directamente conectados. H3C también documenta que los paquetes HGMPv2 utilizan por defecto la dirección multicast 01:80:C2:00:00:0A, con otras direcciones configurables dentro de 01:80:C2:00:00:20-2F.

ProyectoRed utiliza esa trama como señal de vecino local y conserva la MAC de origen. En esta etapa no interpreta campos internos de NDP que no están suficientemente documentados; la MAC obtenida se usa para restringir el ARP posterior a ese mismo vecino y recuperar su IPv4 cuando el equipo responda por ARP.

### HPSW de HP

HPSW (HP Switch Protocol) es un mecanismo legacy que Wireshark documenta sobre HP Extended LLC. El formato incluye TLV para nombre del dispositivo, versión, IP y MAC propia del equipo.

ProyectoRed reconoce la encapsulación HP Extended LLC y extrae, cuando están presentes, nombre, IPv4 y MAC del propio equipo. Esta ruta está pensada especialmente para switches HP antiguos y no reemplaza LLDP.

### Dell ISDP

ISDP de Dell es compatible con el formato de descubrimiento de CDP. La lógica existente que interpreta las tramas CDP ya cubre el formato de cableado empleado por ISDP/CDP; no se agrega un segundo parser que duplique esa misma estructura.

### Alcance

Estas incorporaciones son exclusivamente señales adicionales de descubrimiento. No reemplazan LLDP, no modifican la estrategia ARP existente y no convierten ProyectoRed en un escáner de la red.

## Alcance de la primera versión

El núcleo de descubrimiento se mantiene limitado a:

IP + MAC + fabricante cuando se pueda obtener + nombre cuando exista

La comprobación de acceso se limita a servicios de administración habituales sobre la IP ya detectada.

No incorporar todavía:

- detección de puertos;
- sistema operativo;
- SNMP;
- inventario avanzado;
- base de datos;
- topología;
- mapas.

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

## Instalador Windows

La publicación autónoma y el instalador están separados.

El script:

~~~text
publicar-windows.bat
~~~

genera la publicación en:

~~~text
dist/windows-x64/
~~~

El instalador de Inno Setup se encuentra en:

~~~text
installer/ProyectoRed.iss
~~~

y se puede compilar mediante:

~~~text
installer/crear-instalador-windows.bat
~~~

El instalador incluye la publicación self-contained de ProyectoRed y crea accesos directos en el menú Inicio y en el escritorio.

### Npcap y el instalador

Npcap sigue siendo una dependencia de sistema para la captura Ethernet en Windows.

El instalador no incluye una copia de Npcap en el repositorio. Para empaquetar e instalar Npcap junto con ProyectoRed se debe utilizar una distribución Npcap OEM con los derechos de redistribución correspondientes.

El instalador deja preparado el punto de integración para Npcap OEM. Cuando exista una copia legítimamente redistribuible del instalador OEM, puede incorporarse localmente en:

~~~text
installer/dependencies/npcap-oem.exe
~~~

sin subir ese archivo al repositorio, y habilitar la línea correspondiente en installer/ProyectoRed.iss.

Mientras Npcap no esté instalado, el instalador avisa al finalizar la instalación. La aplicación también informa del problema cuando intenta realizar una captura.

### Objetivo de instalación

El flujo de campo queda así:

~~~text
Instalador ProyectoRed
        |
        +--> instala ProyectoRed.Web.exe
        |
        +--> .NET ya viene incluido
        |
        +--> verifica si Npcap está instalado
        |
        +--> crea accesos directos
        |
        v
ProyectoRed.Web.exe
        |
        +--> localhost:5094
        +--> navegador
        +--> captura Ethernet mediante Npcap
~~~

La instalación de ProyectoRed requiere permisos de administrador porque se instala en Program Files. La ejecución posterior no requiere instalar .NET por separado.

## Acceso y métodos de administración del dispositivo

Después de detectar una IPv4, ProyectoRed comprueba automáticamente los métodos de administración de esa única IP.

La secuencia es:

~~~text
IP detectada
    |
    +--> HTTP  : TCP 80
    +--> HTTPS : TCP 443
    +--> HTTPS : TCP 8443
    +--> HTTP  : TCP 8080
    +--> SSH   : TCP 22
    +--> Telnet: TCP 23
~~~

Las seis comprobaciones se realizan en paralelo para que un puerto cerrado no haga esperar secuencialmente a los demás.

Para HTTP/HTTPS se establece una conexión directa y se valida la respuesta del protocolo. HTTPS realiza un handshake TLS; el certificado no se utiliza para validar confianza, porque el objetivo de esta prueba es determinar si existe un servicio de administración HTTPS en el dispositivo.

Para SSH se comprueba el banner inicial del protocolo. Para Telnet se comprueba que el puerto TCP 23 acepte una conexión; Telnet no dispone de un banner universal tan fiable como SSH, por lo que la interfaz debe entenderlo como "puerto Telnet accesible", no como una autenticación realizada.

La interfaz puede mostrar, por ejemplo:

~~~text
Métodos de acceso detectados

HTTPS   TCP 443     [Abrir]
SSH     TCP 22      [Copiar comando]
~~~

Cada servicio detectado presenta su propia acción. Para HTTP/HTTPS se ofrece una URL comprobada para abrirla directamente; para SSH/Telnet se puede copiar un comando como:

~~~text
ssh 10.0.1.20
telnet 10.0.1.20 23
~~~

La detección de métodos de administración se realiza solamente contra la IPv4 que ProyectoRed ya identificó. No se escanean otras direcciones de la red.

La comparación de subred continúa siendo:

~~~text
(IP de la PC AND máscara)
==
(IP del dispositivo AND máscara)
~~~

Si la PC y el dispositivo están en redes diferentes, la comprobación de servicios no se ejecuta como si fueran accesibles directamente y se muestra la guía de configuración IPv4 temporal.

Si no existe un servicio web pero sí SSH o Telnet, no se considera un fallo: ProyectoRed muestra el método de acceso encontrado y su comando correspondiente.

Si no se detecta ningún método, se informa explícitamente:

~~~text
No se detectaron HTTP, HTTPS, SSH ni Telnet.
~~~

Esta funcionalidad no realiza autenticación, no intenta descubrir credenciales y no modifica la configuración del dispositivo. Tampoco modifica automáticamente la configuración de red de Windows.

## Clasificación de IPv4

La información principal de ProyectoRed sigue siendo:

~~~text
IP + MAC + Nombre
~~~

La clasificación de la dirección no se guarda en el modelo DispositivoDetectado. Se calcula al momento de mostrar el resultado mediante ClasificadorDireccionService.

Las categorías básicas implementadas son:

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

Esta clasificación sirve como información auxiliar para el técnico y no cambia el objetivo principal del proyecto: descubrir la IPv4 del dispositivo conectado por UTP y facilitar el acceso a su interfaz cuando sea posible.

## Descubrimiento sin puerta de enlace

La puerta de enlace IPv4 ya no es un requisito para ejecutar la detección.

Cuando la interfaz Ethernet tiene una IPv4, ProyectoRed usa esa dirección y su máscara para construir los objetivos ARP. La puerta de enlace, si existe, se agrega como primer candidato, pero ya no es un requisito.

Cuando no existe puerta de enlace o la interfaz no tiene una IPv4, ProyectoRed inicia igualmente la captura y utiliza los protocolos de capa 2. La búsqueda 169.254/16 se conserva como respaldo ampliado.

La estrategia de descubrimiento en una conexión directa prioriza protocolos de capa 2 que identifican al vecino del puerto:

~~~text
LLDP
CDP
STP/RSTP
EDP
~~~

Si el dispositivo anuncia LLDP, ProyectoRed utiliza la MAC de origen del anuncio y, cuando el anuncio contiene un **Management Address TLV** IPv4, también obtiene la IP de gestión.

CDP permite identificar el vecino Cisco mediante su MAC y el TLV Device-ID.

Cuando no aparece LLDP/CDP, ProyectoRed puede obtener una respuesta ARP pasiva si el dispositivo emite tráfico visible para la interfaz. Para evitar tomar tráfico unicast ajeno como si fuera el objetivo, la captura no necesita trabajar en modo promiscuo para este escenario.

### Modos de búsqueda

La interfaz permite elegir un criterio antes de iniciar la detección:

~~~text
Automática
Por IP
Por MAC
~~~

#### Búsqueda automática

No se conoce ni la IP ni la MAC. ProyectoRed mantiene el comportamiento actual:

~~~text
LLDP / CDP / EDP / FDP / NDP / HPSW / STP
                    ↓
              captura pasiva
                    ↓
                   ARP
                    ↓
          consolidación y heurística
~~~

La búsqueda ARP puede ampliarse a la subred local, Link-Local 169.254/16 y rangos de respaldo según el escenario. La identificación heurística sigue asociando la IP y la MAC observadas y no toma el primer ARP como si fuera automáticamente el dispositivo conectado.

#### Búsqueda por IP

Cuando el técnico conoce la IP, ProyectoRed realiza una consulta ARP dirigida contra esa única dirección para obtener su MAC y los datos asociados que puedan obtenerse.

Si existe un registro histórico de la misma IP en la interfaz seleccionada, ProyectoRed puede recuperar únicamente la MAC guardada y utilizarla para buscar la **IPv4 actual**. La IP histórica no se considera permanente porque puede haber cambiado.

Si la MAC histórica ya no responde, se mantiene un fallback mediante ARP directo a la IP solicitada.

#### Búsqueda por MAC

Cuando el técnico conoce la MAC que figura en el chasis o etiqueta del equipo, puede introducirla como:

~~~text
AA:BB:CC:DD:EE:FF
AA-BB-CC-DD-EE-FF
AABBCCDDEEFF
~~~

ProyectoRed normaliza la dirección y acepta como coincidencia solamente una MAC observada que sea igual a la MAC buscada.

El flujo es:

~~~text
MAC conocida
     ↓
LLDP / CDP / EDP / FDP / NDP / HPSW / STP
     ↓
ARP sobre los mismos rangos de búsqueda
     ↓
¿MAC observada == MAC buscada?
     ↓
     Sí
     ↓
IPv4 + MAC + nombre + fabricante
~~~

Una MAC conocida permite identificar el par IP/MAC sin depender de la puntuación heurística cuando el equipo responde con esa dirección. El modo por MAC también amplía la búsqueda a los rangos de respaldo ya existentes para cubrir equipos cuya IP fija esté fuera de la red configurada en la PC.

## Próximo paso

La búsqueda por IP, la búsqueda por MAC y la reutilización del historial ya forman parte del flujo de descubrimiento. La siguiente etapa es validar los tres caminos con hardware real:

~~~text
1. IP conocida → MAC actual
2. MAC conocida → IP actual
3. Sin IP/MAC → descubrimiento automático y heurística
4. IP histórica → MAC histórica → búsqueda de IP actual
~~~

Las pruebas deben contemplar dispositivos con IP fija, con y sin puerta de enlace, PC con DHCP y equipos cuya IP esté en otra red. El objetivo sigue siendo mantener el descubrimiento masivo como fallback sin presentar una inferencia ARP como certeza física.

## Forma de desarrollo

El proyecto tiene también un objetivo educativo. Se está construyendo como práctica de C#, ASP.NET Core y redes.

La metodología acordada es:

1. Avanzar paso a paso.
2. Explicar el concepto necesario antes de aplicar cada cambio importante.
3. Mantener nombres de variables, clases y métodos en español cuando sea razonable.
4. Mantener comentarios y documentación en español.
5. No adelantar componentes que todavía no sean necesarios.
6. Cuando una modificación sea suficientemente concreta, puede realizarse directamente en el repositorio para que luego se pruebe mediante git pull, dotnet build y dotnet run.

## Continuidad

El contexto completo para retomar la tutoría y las decisiones técnicas del proyecto se encuentra en:

docs/PROMPT_CONTINUIDAD.md
