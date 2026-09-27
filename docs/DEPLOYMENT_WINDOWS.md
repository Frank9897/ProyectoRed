# Despliegue de ProyectoRed en Windows

## Objetivo

La PC de campo no debe necesitar instalar .NET.

ProyectoRed se publica para **Windows x64** como una aplicación:

- self-contained;
- single-file;
- HTTP local;
- sin Internet para su funcionamiento web.

La publicación incluye el runtime de .NET y las dependencias administradas dentro del ejecutable. Las aplicaciones .NET self-contained incluyen el runtime necesario y no requieren que el equipo tenga el runtime de .NET instalado previamente.

## Publicar

Desde la raíz del repositorio:

~~~bat
publicar-windows.bat
~~~

El script ejecuta la publicación de:

~~~text
src/ProyectoRed.Web/ProyectoRed.Web.csproj
~~~

usando el perfil:

~~~text
src/ProyectoRed.Web/Properties/PublishProfiles/WindowsSelfContained.pubxml
~~~

También puede ejecutarse directamente con:

~~~bat
dotnet publish "src\ProyectoRed.Web\ProyectoRed.Web.csproj" -c Release -p:PublishProfile=WindowsSelfContained
~~~

La publicación está dirigida a:

~~~text
win-x64
~~~

La combinación de self-contained + single-file es específica del sistema operativo y arquitectura. Para otra arquitectura hay que generar una publicación distinta.

## Resultado esperado

El ejecutable de publicación se genera dentro de:

~~~text
src/ProyectoRed.Web/bin/Release/net10.0/win-x64/publish/
~~~

El objetivo del perfil es obtener:

~~~text
ProyectoRed.Web.exe
~~~

como artefacto principal de distribución.

## Ejecución

En la PC de campo:

1. Ejecutar ProyectoRed.Web.exe.
2. La aplicación inicia ASP.NET Core en:

~~~text
http://127.0.0.1:5094
~~~

3. En Windows se abre automáticamente el navegador predeterminado.
4. El navegador trabaja contra la aplicación local; no necesita Internet.

El proyecto usa HTTP local de forma intencional para no depender de un certificado HTTPS de desarrollo.

## Por qué no hace falta .NET

En una publicación self-contained, el ejecutable se distribuye con el runtime de .NET y las dependencias necesarias para la aplicación. Por eso el equipo de campo no necesita tener instalado el runtime de .NET por separado.

La publicación single-file agrupa la aplicación en un ejecutable. El perfil también incorpora las bibliotecas nativas necesarias del runtime al paquete ejecutable.

## Npcap

Hay una dependencia diferente a .NET:

**Npcap**.

ProyectoRed utiliza SharpPcap para captura de paquetes Ethernet en Windows, por lo que el controlador de captura Npcap debe estar instalado en la PC donde se realiza la captura.

Npcap no es un componente administrado de .NET. Una publicación self-contained no instala por sí sola este controlador.

Además, la edición gratuita de Npcap no permite redistribuirla externamente con un producto. Para incluir Npcap dentro de un instalador o distribuirlo junto con ProyectoRed, el proyecto necesitaría la licencia correspondiente de **Npcap OEM**.

Por ahora, la estrategia es:

~~~text
ProyectoRed.Web.exe  -> incluye .NET
Npcap                 -> componente del sistema para captura
~~~

Más adelante se puede preparar un instalador de campo que compruebe Npcap e indique al técnico qué falta, o integrar un instalador de Npcap OEM cuando corresponda.

## Verificación inicial

La primera prueba en Windows debe hacerse en una PC que permita comprobar:

- que ProyectoRed.Web.exe arranca sin instalar .NET;
- que el navegador se abre automáticamente;
- que http://127.0.0.1:5094 muestra la página;
- que CSS y JavaScript locales funcionan;
- que la aplicación puede enumerar las interfaces de red.

Después se verifica la captura con Npcap.

## Nota

La publicación es para **Windows x64**. El proyecto de desarrollo continúa ejecutándose normalmente en Debian con .NET 10.

No se debe copiar una instalación completa de .NET a la PC de campo como solución de despliegue: esa dependencia ya está contemplada por la publicación self-contained.
