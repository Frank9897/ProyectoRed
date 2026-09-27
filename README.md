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
- Enumeración de interfaces mediante NetworkInterface.GetAllNetworkInterfaces().
- Filtro por OperationalStatus.Up.
- Filtro por NetworkInterfaceType.Ethernet.
- Detección de interfaz física específica para Linux y Windows.
- Registro mediante inyección de dependencias.
- Captura de paquetes con SharpPcap.
- Análisis Ethernet con PacketDotNet.
- Prueba de captura limitada a unos segundos para evitar ejecución indefinida.
- Detección de paquetes LLDP.
- Lectura del System Name de LLDP cuando el paquete lo proporciona.
- Publicación prevista como ejecutable Windows x64 self-contained y single-file.

### Verificación actual

En Debian ya se comprobó que:

- enp2s0 puede abrirse con SharpPcap ejecutando la aplicación con permisos adecuados.
- La captura Ethernet funciona.
- PacketDotNet puede interpretar paquetes Ethernet.
- En una prueba de 5 segundos no apareció LLDP.

La ausencia de LLDP no implica un fallo del capturador; el dispositivo o la red de prueba puede no estar enviando anuncios LLDP.

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

## Próximo paso

Antes de continuar agregando mecanismos de descubrimiento, queda preparada la parte de **despliegue autónomo para Windows**.

Después se continuará con la estrategia de descubrimiento de IP/MAC/Nombre. No se debe tomar el primer paquete ARP observado como si fuera automáticamente el dispositivo objetivo, porque puede pertenecer a otro equipo de la red.

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
