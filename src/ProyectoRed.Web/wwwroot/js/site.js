// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

document.addEventListener("DOMContentLoaded", function () {
    const interfazRed = document.getElementById("interfazRed");
    const btnComenzar = document.getElementById("btnComenzar");
    const estadoDeteccion =
        document.getElementById("estadoDeteccion");

    const estadoInterfaz =
        document.getElementById("estadoInterfaz");

    const direccionIpObjetivo =
        document.getElementById("direccionIpObjetivo");

    const resultadoDeteccion =
        document.getElementById("resultadoDeteccion");

    const resultadoEnlace =
        document.getElementById("resultadoEnlace");

    const resultadoIp =
        document.getElementById("resultadoIp");

    const resultadoMac =
        document.getElementById("resultadoMac");

    const resultadoTipoDireccion =
        document.getElementById("resultadoTipoDireccion");

    const resultadoFabricante =
        document.getElementById("resultadoFabricante");

    const resultadoMascaraLocal =
        document.getElementById("resultadoMascaraLocal");

    const alertaResultadoDeteccion =
        document.getElementById("alertaResultadoDeteccion");

    const detalleFalloDeteccion =
        document.getElementById("detalleFalloDeteccion");

    const resultadoMetodo =
        document.getElementById("resultadoMetodo");

    const tiemposDeteccion =
        document.getElementById("tiemposDeteccion");

    const tiempoTranscurrido =
        document.getElementById("tiempoTranscurrido");

    const tiempoEstimado =
        document.getElementById("tiempoEstimado");

    const faseDeteccion =
        document.getElementById("faseDeteccion");

    const resultadoSondasArp =
        document.getElementById("resultadoSondasArp");

    const metodosAcceso =
        document.getElementById("metodosAcceso");

    const listaMetodosAcceso =
        document.getElementById("listaMetodosAcceso");

    const btnAbrirInterfaz =
        document.getElementById("btnAbrirInterfaz");

    const mensajeAcceso =
        document.getElementById("mensajeAcceso");

    const configuracionManual =
        document.getElementById("configuracionManual");

    const configuracionIp =
        document.getElementById("configuracionIp");

    const configuracionMascara =
        document.getElementById("configuracionMascara");

    if (!interfazRed || !btnComenzar) {
        return;
    }

    interfazRed.addEventListener("change", function () {
        const opcion =
            interfazRed.options[interfazRed.selectedIndex];

        if (!opcion || !opcion.value) {
            estadoInterfaz.textContent =
                "IPv4 actual: seleccione una interfaz.";

            return;
        }

        const ipActual =
            opcion.dataset.ip || "";

        estadoInterfaz.textContent =
            "IPv4 actual: " +
            (ipActual || "sin IPv4 configurada.");
    });

    async function comprobarAccesoDispositivoAsync(
        nombreInterfaz,
        direccionIP,
        ventanaInterfaz = null)
    {
        // respuesta contiene el estado de acceso que devuelve el backend.
        // Cambiarla modifica la fuente de datos usada para representar
        // HTTP, HTTPS, SSH y Telnet en pantalla.
        let respuesta;

        try
        {
            // respuestaHttp es la respuesta HTTP del endpoint local de ASP.NET.
            // Cambiar la ruta modifica el backend que realiza las pruebas.
            const respuestaHttp =
                await fetch(
                    "/Home/AccesoDispositivo?nombreInterfaz=" +
                    encodeURIComponent(nombreInterfaz) +
                    "&direccionIP=" +
                    encodeURIComponent(direccionIP));

            // respuesta = JSON deserializado con los resultados de acceso.
            // Cambiar este objeto exige adaptar todos los campos consumidos
            // por la interfaz.
            respuesta =
                await respuestaHttp.json();

            if (!respuestaHttp.ok)
            {
                throw new Error(
                    respuesta.mensaje ||
                    "No se pudo comprobar el acceso al dispositivo.");
            }

            // Renderizamos siempre la lista para que el técnico pueda ver
            // los métodos detectados aunque no exista una interfaz web.
            renderizarMetodosAcceso(
                respuesta.metodosAcceso || []);

            if (respuesta.puedeAbrirInterfaz)
            {
                // mensajeAcceso describe el resultado de la comprobación web.
                // Cambiarlo solo modifica el texto informativo.
                mensajeAcceso.textContent =
                    respuesta.mensaje || "";

                mensajeAcceso.className =
                    "alert alert-success mt-3 mb-0";

                if (ventanaInterfaz)
                {
                    ventanaInterfaz.opener = null;
                    ventanaInterfaz.location.href =
                        respuesta.urlInterfaz;
                }
            }
            else
            {
                if (ventanaInterfaz)
                {
                    ventanaInterfaz.close();
                }

                mensajeAcceso.textContent =
                    respuesta.mensaje || "";

                mensajeAcceso.className =
                    "alert alert-warning mt-3 mb-0";

                if (respuesta.configuracionManual &&
                    respuesta.configuracionManual.direccionIP)
                {
                    configuracionIp.textContent =
                        respuesta.configuracionManual.direccionIP;

                    configuracionMascara.textContent =
                        respuesta.configuracionManual.mascaraRed;

                    configuracionManual.classList.remove("d-none");
                }
                else if (!respuesta.metodosAcceso ||
                         respuesta.metodosAcceso.length === 0)
                {
                    configuracionManual.classList.add("d-none");
                }
            }

            return respuesta;
        }
        catch (error)
        {
            if (ventanaInterfaz)
            {
                ventanaInterfaz.close();
            }

            mensajeAcceso.textContent =
                error.message;

            mensajeAcceso.className =
                "alert alert-danger mt-3 mb-0";

            return null;
        }
    }

    function renderizarMetodosAcceso(
        metodos)
    {
        // listaMetodos contiene exclusivamente los métodos que el backend
        // confirmó. Cambiarla modifica la representación visual.
        listaMetodosAcceso.innerHTML = "";

        if (!Array.isArray(metodos) ||
            metodos.length === 0)
        {
            metodosAcceso.classList.remove("d-none");

            // mensajeSinMetodos explica que se comprobaron los servicios
            // pero ninguno respondió de forma compatible.
            const mensajeSinMetodos =
                document.createElement("div");

            mensajeSinMetodos.className =
                "text-muted small";

            mensajeSinMetodos.textContent =
                "No se detectaron HTTP, HTTPS, SSH ni Telnet.";

            listaMetodosAcceso.appendChild(
                mensajeSinMetodos);

            return;
        }

        metodosAcceso.classList.remove("d-none");

        for (const metodo of metodos)
        {
            // filaMetodo representa una línea visual de un método de acceso.
            // Cambiarla modifica el formato de cada servicio detectado.
            const filaMetodo =
                document.createElement("div");

            filaMetodo.className =
                "d-flex flex-wrap align-items-center " +
                "justify-content-between gap-2 border-bottom py-2";

            // informacionMetodo agrupa nombre y puerto del servicio.
            const informacionMetodo =
                document.createElement("div");

            // nombreMetodo es la etiqueta HTTP, HTTPS, SSH o Telnet.
            const nombreMetodo =
                document.createElement("strong");

            nombreMetodo.textContent =
                metodo.nombre || "Método";

            // puertoMetodo muestra el puerto TCP comprobado.
            // Cambiarlo solo cambia la información visual devuelta por el backend.
            const puertoMetodo =
                document.createElement("span");

            puertoMetodo.className =
                "text-muted ms-2";

            puertoMetodo.textContent =
                "TCP " +
                String(metodo.puerto || "");

            informacionMetodo.appendChild(
                nombreMetodo);

            informacionMetodo.appendChild(
                puertoMetodo);

            filaMetodo.appendChild(
                informacionMetodo);

            if (metodo.url)
            {
                // enlaceMetodo permite abrir directamente el servicio web
                // confirmado. No usa una URL inventada por la interfaz.
                const enlaceMetodo =
                    document.createElement("a");

                enlaceMetodo.href =
                    metodo.url;

                enlaceMetodo.target =
                    "_blank";

                enlaceMetodo.rel =
                    "noopener noreferrer";

                enlaceMetodo.className =
                    "btn btn-sm btn-outline-primary";

                enlaceMetodo.textContent =
                    "Abrir";

                filaMetodo.appendChild(
                    enlaceMetodo);
            }
            else if (metodo.comando)
            {
                // botonComando copia SSH/Telnet al portapapeles sin intentar
                // autenticarse ni modificar el dispositivo.
                const botonComando =
                    document.createElement("button");

                botonComando.type =
                    "button";

                botonComando.className =
                    "btn btn-sm btn-outline-secondary";

                botonComando.textContent =
                    "Copiar comando";

                // comando es el texto exacto que queremos copiar.
                // Cambiarlo modifica el comando que recibirá el técnico.
                const comando =
                    metodo.comando;

                botonComando.addEventListener(
                    "click",
                    async function () {
                        try
                        {
                            await navigator.clipboard.writeText(
                                comando);

                            botonComando.textContent =
                                "Copiado";
                        }
                        catch
                        {
                            botonComando.textContent =
                                comando;
                        }
                    });

                filaMetodo.appendChild(
                    botonComando);
            }

            listaMetodosAcceso.appendChild(
                filaMetodo);
        }
    }

    btnAbrirInterfaz.addEventListener("click", async function () {
        // nombreInterfaz identifica la NIC que está físicamente conectada.
        // Cambiarla podría dirigir las pruebas de acceso por otra interfaz.
        const nombreInterfaz =
            interfazRed.value;

        // direccionIP es la IPv4 que ProyectoRed ya mostró como resultado.
        // Cambiarla modifica el dispositivo contra el que se probará el acceso.
        const direccionIP =
            resultadoIp.textContent;

        if (!nombreInterfaz ||
            !direccionIP ||
            direccionIP === "No disponible" ||
            direccionIP === "No determinada")
        {
            mensajeAcceso.textContent =
                "No hay una dirección IPv4 disponible para abrir el dispositivo.";

            mensajeAcceso.className =
                "alert alert-warning mt-3 mb-0";

            return;
        }

        btnAbrirInterfaz.disabled =
            true;

        mensajeAcceso.classList.add(
            "d-none");

        configuracionManual.classList.add(
            "d-none");

        // ventanaInterfaz se abre durante el clic para evitar que el navegador
        // bloquee la nueva pestaña después de la comprobación asíncrona.
        const ventanaInterfaz =
            window.open(
                "about:blank",
                "_blank");

        if (!ventanaInterfaz)
        {
            mensajeAcceso.textContent =
                "El navegador bloqueó la nueva pestaña. Permita ventanas emergentes para ProyectoRed.";

            mensajeAcceso.className =
                "alert alert-warning mt-3 mb-0";

            btnAbrirInterfaz.disabled =
                false;

            return;
        }

        try
        {
            await comprobarAccesoDispositivoAsync(
                nombreInterfaz,
                direccionIP,
                ventanaInterfaz);
        }
        finally
        {
            btnAbrirInterfaz.disabled =
                false;
        }
    });

    btnComenzar.addEventListener("click", async function () {
        const nombreInterfaz = interfazRed.value;

        if (!nombreInterfaz) {
            estadoDeteccion.textContent =
                "Seleccione una interfaz.";

            return;
        }

        btnComenzar.disabled = true;
        resultadoDeteccion.classList.add("d-none");
        mensajeAcceso.classList.add("d-none");
        configuracionManual.classList.add("d-none");

        tiemposDeteccion.classList.remove("d-none");

        const inicioDeteccion =
            performance.now();

        const deteccionManual =
            direccionIpObjetivo.value.trim().length > 0;

        const estimacionInicialMs =
            deteccionManual
                ? 1500
                : 20000;

        tiempoEstimado.textContent =
            "~" +
            (estimacionInicialMs / 1000)
                .toFixed(0) +
            " s";

        tiempoTranscurrido.textContent =
            "0.0 s";

        faseDeteccion.textContent =
            deteccionManual
                ? "ARP dirigido"
                : "Escuchando vecinos";

        const actualizadorTiempo =
            setInterval(function () {
                const transcurrido =
                    performance.now() -
                    inicioDeteccion;

                tiempoTranscurrido.textContent =
                    (transcurrido / 1000)
                        .toFixed(1) +
                    " s";

                if (!deteccionManual)
                {
                    if (transcurrido < 6000)
                    {
                        faseDeteccion.textContent =
                            "Escuchando vecinos";
                    }
                    else if (transcurrido < estimacionInicialMs)
                    {
                        faseDeteccion.textContent =
                            "Sondeo ARP";
                    }
                    else
                    {
                        faseDeteccion.textContent =
                            "Sondeo ARP (tiempo extendido)";
                    }
                }
            }, 100);

        try {
            const parametros =
                new URLSearchParams();

            parametros.set(
                "nombreInterfaz",
                nombreInterfaz);

            if (direccionIpObjetivo.value.trim()) {
                parametros.set(
                    "direccionIPObjetivo",
                    direccionIpObjetivo.value.trim());
            }

            const respuesta = await fetch(
                "/Home/Descubrir?" +
                parametros.toString()
            );

            const datos = await respuesta.json();

            if (!respuesta.ok) {
                throw new Error(
                    datos.mensaje ||
                    "No se pudo realizar la detección."
                );
            }

            const enlaceActivo =
                datos.enlaceActivo === true;

            const macDetectada =
                datos.direccionMac || "";

            const ipDetectada =
                datos.direccionIP || "";

            const fabricanteDetectado =
                datos.fabricante || "";

            const mascaraLocalDetectada =
                datos.mascaraLocal || "";

            const metodoDetectado =
                datos.metodoDeteccion || "";

            const cantidadSondas =
                Number(datos.cantidadSondasArp || 0);

            const faseFinal =
                datos.faseDeteccion || "";

            const tipoDireccionDetectada =
                datos.tipoDireccionIP || "";

            resultadoEnlace.textContent =
                enlaceActivo
                    ? "Activo"
                    : "Sin enlace";

            resultadoIp.textContent =
                ipDetectada || "No determinada";

            resultadoMac.textContent =
                macDetectada || "No disponible";

            resultadoTipoDireccion.textContent =
                tipoDireccionDetectada || "No disponible";

            resultadoFabricante.textContent =
                fabricanteDetectado ||
                "No identificado";

            resultadoMascaraLocal.textContent =
                mascaraLocalDetectada ||
                "No disponible";

            resultadoMetodo.textContent =
                metodoDetectado || "Búsqueda automática";

            resultadoSondasArp.textContent =
                cantidadSondas.toLocaleString("es-AR");

            faseDeteccion.textContent =
                faseFinal || "Finalizada";

            if (typeof datos.tiempoTranscurridoMs === "number" &&
                datos.tiempoTranscurridoMs > 0)
            {
                tiempoTranscurrido.textContent =
                    (datos.tiempoTranscurridoMs / 1000)
                        .toFixed(1) +
                    " s";
            }

            mensajeAcceso.classList.add("d-none");
            configuracionManual.classList.add("d-none");
            alertaResultadoDeteccion.classList.add("d-none");
            detalleFalloDeteccion.textContent = "";

            if (!macDetectada) {
                resultadoDeteccion.classList.add("d-none");
                alertaResultadoDeteccion.classList.remove("d-none");
                detalleFalloDeteccion.textContent =
                    datos.mensajeEstado ||
                    "No se encontró una MAC ni una IP del dispositivo.";
            }
            else {
                resultadoDeteccion.classList.remove("d-none");
            }

            if (ipDetectada) {
                btnAbrirInterfaz.classList.remove("d-none");

                // La comprobación automática usa la IP ya detectada y no
                // abre ninguna ventana. Se ejecuta en segundo plano para
                // no alterar los contadores de tiempo del descubrimiento.
                comprobarAccesoDispositivoAsync(
                    nombreInterfaz,
                    ipDetectada);
            }
            else {
                btnAbrirInterfaz.classList.add("d-none");
                metodosAcceso.classList.add("d-none");
            }

            if (macDetectada) {
                estadoDeteccion.textContent =
                    datos.mensajeEstado ||
                    "Detección finalizada.";
            }
            else if (enlaceActivo) {
                estadoDeteccion.textContent =
                    datos.mensajeEstado ||
                    "El enlace UTP está activo, pero no se pudo identificar el dispositivo.";
            }
            else {
                estadoDeteccion.textContent =
                    datos.mensajeEstado ||
                    "No hay un enlace Ethernet activo.";
            }
        }
        catch (error) {
            estadoDeteccion.textContent =
                error.message;
        }
        finally {
            clearInterval(
                actualizadorTiempo);

            const tiempoFinal =
                performance.now() -
                inicioDeteccion;

            tiempoTranscurrido.textContent =
                (tiempoFinal / 1000).toFixed(1) +
                " s";

            if (!faseDeteccion.textContent ||
                faseDeteccion.textContent ===
                    "Preparando...")
            {
                faseDeteccion.textContent =
                    "Finalizada";
            }

            btnComenzar.disabled = false;
        }
    });
});
