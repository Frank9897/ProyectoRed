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
    +--> detección de interfaz física según sistema operativo
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
~~~

La interfaz web y la lógica de descubrimiento deben mantenerse separadas para poder ampliar el proyecto posteriormente.

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
- Servicio AccesoDispositivoService para validar el acceso a la interfaz web del dispositivo.
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

Esta estrategia es **pasiva** y está pensada para el escenario de conexión directa. No realiza todavía un escaneo de toda la subred.

La ausencia de tráfico significa que no siempre será posible obtener toda la información: un equipo silencioso puede no proporcionar una IPv4 o un nombre durante la ventana de captura.

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

## Acceso a la interfaz del dispositivo

Después de detectar un dispositivo con una IPv4, la interfaz muestra el botón:

~~~text
Abrir interfaz del dispositivo
~~~

Al pulsarlo, el backend analiza la configuración IPv4 actual de la interfaz seleccionada.

Se compara:

~~~text
(IP de la PC AND máscara)
==
(IP del dispositivo AND máscara)
~~~

Si ambas direcciones pertenecen a la misma red, ProyectoRed abre:

~~~text
http://IP-DEL-DISPOSITIVO
~~~

en una nueva pestaña del navegador.

Si están en redes diferentes, ProyectoRed no cambia automáticamente la configuración de Windows. Muestra la IP y la máscara actuales, informa de la situación y, cuando existe una dirección posible, propone una configuración temporal para acceder a un dispositivo con IP fija.

La propuesta deja la puerta de enlace vacía porque el objetivo de esta configuración temporal es acceder al dispositivo de forma local.

También se consulta si la interfaz utiliza DHCP. Si está en DHCP, el mensaje indica que se debe comprobar que exista un servidor DHCP que entregue una dirección de la misma red. Si está configurada manualmente, se informa de que puede ser necesario cambiar temporalmente la configuración IPv4.

Esta funcionalidad no realiza modificaciones automáticas en la configuración de red de Windows.

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

Cuando la interfaz Ethernet tiene una IPv4 y una puerta de enlace, ProyectoRed realiza una consulta ARP dirigida al gateway para conservar el comportamiento que ya funcionaba con routers/modems.

Cuando no existe puerta de enlace, o la interfaz no tiene una IPv4, ProyectoRed inicia igualmente la captura durante una ventana limitada.

La estrategia de descubrimiento en una conexión directa prioriza protocolos de capa 2 que identifican al vecino del puerto:

~~~text
LLDP
CDP
~~~

Si el dispositivo anuncia LLDP, ProyectoRed utiliza la MAC de origen del anuncio y, cuando el anuncio contiene un **Management Address TLV** IPv4, también obtiene la IP de gestión.

CDP permite identificar el vecino Cisco mediante su MAC y el TLV Device-ID.

Cuando no aparece LLDP/CDP, ProyectoRed puede obtener una respuesta ARP pasiva si el dispositivo emite tráfico visible para la interfaz. Para evitar tomar tráfico unicast ajeno como si fuera el objetivo, la captura no necesita trabajar en modo promiscuo para este escenario.

### Detección manual

La interfaz incluye una sección **Detección manual** con:

~~~text
IP del dispositivo
IP local de prueba
~~~

La primera dirección es la IP concreta que se desea consultar.

Cuando se completa, ProyectoRed envía una **única consulta ARP dirigida a esa IP**. No realiza un escaneo de la subred ni prueba automáticamente miles de direcciones.

La IP local de prueba es opcional. Solo se utiliza como dirección de origen de la consulta ARP cuando la interfaz de la PC no tiene una IPv4 configurada.

Esta configuración manual **no modifica la configuración de Windows**.

Por lo tanto, si el técnico conoce la IP fija/default del dispositivo, puede hacer una consulta puntual incluso cuando la PC todavía no tiene IPv4 o puerta de enlace.

La captura sin una IP objetivo conocida no puede garantizar la identificación de un dispositivo completamente silencioso. El enlace físico puede estar activo aunque el equipo remoto no anuncie LLDP/CDP ni genere tráfico ARP durante la ventana de captura.

Además, la interfaz diferencia entre:

~~~text
Enlace UTP activo
    +
Dispositivo identificado

y

Enlace UTP activo
    +
Sin información identificable todavía
~~~

Esto evita mostrar **“no hay dispositivo conectado”** cuando en realidad el enlace Ethernet está activo pero no se obtuvo una identidad de capa 2/3.

## Próximo paso

Con la parte de despliegue y acceso a la interfaz preparada, el siguiente trabajo sigue siendo comprobar el descubrimiento con un dispositivo conectado directamente por UTP y, a partir de los resultados, mejorar la forma de presentar IP/MAC/Nombre sin convertir ProyectoRed en un scanner de subred.

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
