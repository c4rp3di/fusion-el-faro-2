package com.vigia.faro.forense

import com.vigia.core.red.UtilRed
import com.vigia.faro.Riesgo

/** Convierte los reenvíos de puertos UPnP del router en hallazgos. */
object AnalisisUpnp {

    private val PUERTOS_PELIGROSOS = setOf(21, 22, 23, 2323, 80, 139, 445, 554, 3389, 5555, 5900, 7547, 8000, 8080, 8291, 9100, 37215)

    fun analizar(datos: DatosForenses, r: UpnpAvanzado.Resultado, ipsConocidas: Set<String>) {
        val lineas = ArrayList<String>()
        lineas.add("Servicio: " + r.servicio.substringAfterLast(':', r.servicio).ifEmpty { r.servicio })
        if (r.ipExterna != null) lineas.add("IP que ve internet: " + r.ipExterna)
        if (r.mapeos.isEmpty()) lineas.add("Sin reenvíos de puertos abiertos por UPnP.")
        for (m in r.mapeos) {
            lineas.add(
                m.protocolo + " " + m.puertoExterno + " → " + m.clienteInterno + ":" + m.puertoInterno +
                    (if (m.descripcion.isNotEmpty()) " (" + m.descripcion + ")" else "") + (if (m.activo) "" else " [desactivado]")
            )
        }
        if (!r.completo) lineas.add("Hay más reenvíos de los que se listan (se muestran los primeros).")
        datos.seccion("UPnP: reenvíos de puertos del router", lineas)

        val ext = r.ipExterna
        if (ext != null) {
            val n = UtilRed.parseIpv4(ext)
            if (n != null) {
                val a = (n ushr 24) and 0xFF
                val b = (n ushr 16) and 0xFF
                if (UtilRed.esIpPrivada(n) || (a == 100 && b in 64..127)) {
                    datos.hallazgo(
                        Riesgo.INFO, "El router no tiene IP pública (" + ext + ")",
                        "Está detrás de otra red (CGNAT o doble NAT): los reenvíos de puertos no llegan realmente a internet.",
                        "Nada que hacer.", "UPnP"
                    )
                }
            }
        }

        val activos = r.mapeos.filter { it.activo }
        var contados = 0
        for (m in activos) {
            val peligroso = PUERTOS_PELIGROSOS.contains(m.puertoInterno) || PUERTOS_PELIGROSOS.contains(m.puertoExterno)
            val desconocido = ipsConocidas.isNotEmpty() && !ipsConocidas.contains(m.clienteInterno)
            if (contados >= 8) break
            contados++
            datos.hallazgo(
                if (peligroso) Riesgo.ALTO else Riesgo.MEDIO,
                "Puerto " + m.puertoExterno + "/" + m.protocolo + " del router abierto a internet hacia " + m.clienteInterno + ":" + m.puertoInterno,
                "Un reenvío UPnP deja que internet llegue a ese equipo" + (if (m.descripcion.isNotEmpty()) " (lo creó: «" + m.descripcion + "»)" else "") + "." +
                    (if (peligroso) " Es un puerto de administración o de servicios que se explotan mucho." else "") +
                    (if (desconocido) " Ese equipo no apareció en el barrido." else ""),
                "Si no lo reconoces, elimínalo en el router y desactiva UPnP. Abre solo los puertos que necesites, a mano.", "UPnP"
            )
        }
        if (activos.size > contados) {
            datos.hallazgo(
                Riesgo.MEDIO, (activos.size - contados).toString() + " reenvío(s) UPnP más abiertos a internet",
                "Solo se detallan los primeros; todos están en la sección de UPnP.",
                "Revisa la lista de reenvíos en el router.", "UPnP"
            )
        }
    }
}
