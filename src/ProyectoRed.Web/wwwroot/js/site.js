// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

document.addEventListener("DOMContentLoaded", function () {
    const interfazRed = document.getElementById("interfazRed");
    const btnComenzar = document.getElementById("btnComenzar");
    const estadoDeteccion =
        document.getElementById("estadoDeteccion");

    const resultadoDeteccion =
        document.getElementById("resultadoDeteccion");

    const resultadoIp =
        document.getElementById("resultadoIp");

    const resultadoMac =
        document.getElementById("resultadoMac");

    const resultadoNombre =
        document.getElementById("resultadoNombre");

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

                window.open(
                    datos.urlInterfaz,
                    "_blank",
                    "noopener"
                );
            }
            else {
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

        estadoDeteccion.textContent =
            "Detectando durante unos segundos...";

        try {
            const respuesta = await fetch(
                "/Home/Descubrir?nombreInterfaz=" +
                encodeURIComponent(nombreInterfaz)
            );

            const datos = await respuesta.json();

            if (!respuesta.ok) {
                throw new Error(
                    datos.mensaje ||
                    "No se pudo realizar la detección."
                );
            }

            const macDetectada =
                datos.direccionMac || "";

            const ipDetectada =
                datos.direccionIP || "";

            const nombreDetectado =
                datos.nombre || "";

            if (!macDetectada) {
                estadoDeteccion.textContent =
                    "No se detectó ningún dispositivo durante la prueba.";

                return;
            }

            resultadoIp.textContent =
                ipDetectada || "No disponible";

            resultadoMac.textContent =
                macDetectada;

            resultadoNombre.textContent =
                nombreDetectado || "No disponible";

            mensajeAcceso.classList.add("d-none");
            configuracionManual.classList.add("d-none");
            resultadoDeteccion.classList.remove("d-none");

            estadoDeteccion.textContent =
                "Detección finalizada.";
        }
        catch (error) {
            estadoDeteccion.textContent =
                error.message;
        }
        finally {
            btnComenzar.disabled = false;
        }
    });
});
