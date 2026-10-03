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

    btnAbrirInterfaz.addEventListener("click", async function () {
        const nombreInterfaz = interfazRed.value;
        const direccionIP = resultadoIp.textContent;

        if (!nombreInterfaz || !direccionIP ||
            direccionIP === "No disponible") {
            mensajeAcceso.textContent =
                "No hay una dirección IPv4 disponible para abrir la interfaz.";

            mensajeAcceso.className =
                "alert alert-warning mt-3 mb-0";

            return;
        }

        btnAbrirInterfaz.disabled = true;
        mensajeAcceso.classList.add("d-none");
        configuracionManual.classList.add("d-none");

        // Abrimos la pestaña durante el click del usuario para evitar
        // que el navegador bloquee la apertura después del fetch.
        const ventanaInterfaz =
            window.open("about:blank", "_blank");

        if (!ventanaInterfaz) {
            mensajeAcceso.textContent =
                "El navegador bloqueó la nueva pestaña. Permita ventanas emergentes para ProyectoRed.";

            mensajeAcceso.className =
                "alert alert-warning mt-3 mb-0";

            btnAbrirInterfaz.disabled = false;
            return;
        }

        try {
            const respuesta = await fetch(
                "/Home/AccesoDispositivo?nombreInterfaz=" +
                encodeURIComponent(nombreInterfaz) +
                "&direccionIP=" +
                encodeURIComponent(direccionIP)
            );

            const datos = await respuesta.json();

            if (!respuesta.ok) {
                throw new Error(
                    datos.mensaje ||
                    "No se pudo comprobar el acceso al dispositivo."
                );
            }

            mensajeAcceso.textContent =
                datos.mensaje || "";

            if (datos.puedeAbrirInterfaz) {
                mensajeAcceso.className =
                    "alert alert-success mt-3 mb-0";

                ventanaInterfaz.opener = null;
                ventanaInterfaz.location.href =
                    datos.urlInterfaz;
            }
            else {
                ventanaInterfaz.close();

                mensajeAcceso.className =
                    "alert alert-warning mt-3 mb-0";

                if (datos.configuracionManual &&
                    datos.configuracionManual.direccionIP) {
                    configuracionIp.textContent =
                        datos.configuracionManual.direccionIP;

                    configuracionMascara.textContent =
                        datos.configuracionManual.mascaraRed;

                    configuracionManual.classList.remove("d-none");
                }
            }
        }
        catch (error) {
            ventanaInterfaz.close();

            mensajeAcceso.textContent =
                error.message;

            mensajeAcceso.className =
                "alert alert-danger mt-3 mb-0";
        }
        finally {
            btnAbrirInterfaz.disabled = false;
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
            }
            else {
                btnAbrirInterfaz.classList.add("d-none");
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
