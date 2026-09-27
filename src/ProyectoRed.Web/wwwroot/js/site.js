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

    if (!interfazRed || !btnComenzar) {
        return;
    }

    btnComenzar.addEventListener("click", async function () {
        const nombreInterfaz = interfazRed.value;

        if (!nombreInterfaz) {
            estadoDeteccion.textContent =
                "Seleccione una interfaz.";

            return;
        }

        btnComenzar.disabled = true;
        resultadoDeteccion.classList.add("d-none");

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
