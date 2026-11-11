package com.vigia.faro.bt

import com.vigia.faro.Hallazgo
import com.vigia.faro.Riesgo

class InformeBt(val hallazgos: List<Hallazgo>, val puntuacion: Int, val veredicto: String)

/** Convierte lo que se vio en el aire en hallazgos: rastreadores, visibilidad del teléfono y dispositivos emparejados. */
object AnalisisBt {

    fun analizar(res: ResultadoBt): InformeBt {
        val h = ArrayList<Hallazgo>()
        val lista = res.dispositivos

        val rastreadores = lista.filter { it.rastreador != null && !it.confiable }
        for (x in rastreadores) {
            val cerca = (x.rssi ?: -127) >= -70
            h.add(
                Hallazgo(
                    if (cerca) Riesgo.MEDIO else Riesgo.BAJO,
                    "Posible rastreador cerca: " + x.rastreador + (if (x.cercania != null) " (" + x.cercania + ")" else ""),
                    "Un dispositivo anuncia que es un localizador " + x.rastreador + " (dirección " + x.direccion + (if (x.rssi != null) ", señal " + x.rssi + " dBm" else "") + "). " +
                        "Un análisis puntual no puede saber si te sigue: puede ser tuyo, de alguien cercano, o unos AirPods o un iPhone, que emiten el mismo mensaje. " +
                        "Es sospechoso si no es tuyo y lo vuelves a ver en otros lugares.",
                    "Si no reconoces ninguno, repite el análisis en otro sitio. Si aparece de nuevo, busca un objeto pequeño en tus cosas o en el coche; Android también avisa de rastreadores desconocidos en Ajustes > Seguridad.",
                    "Bluetooth"
                )
            )
        }
        if (res.visible == true) {
            h.add(
                Hallazgo(
                    Riesgo.MEDIO, "Tu teléfono es visible para todos los dispositivos Bluetooth cercanos",
                    "Con la visibilidad activa, cualquiera cerca puede ver el teléfono y probar a emparejarse con él.",
                    "Desactiva la visibilidad: Ajustes > Bluetooth, y deja solo «visible» el tiempo que dure un emparejamiento.", "Bluetooth"
                )
            )
        }
        if (res.nombreTelefono != null && res.nombreTelefono.isNotEmpty() && lista.isNotEmpty()) {
            val n = res.nombreTelefono
            if (Regex("""(?i)(iphone|galaxy|redmi|xiaomi|pixel|oneplus|huawei|de |'s )""").containsMatchIn(n) && n.split(' ').size >= 2) {
                h.add(
                    Hallazgo(
                        Riesgo.INFO, "El nombre Bluetooth de tu teléfono puede identificarte: «" + n + "»",
                        "Quien escanee Bluetooth cerca ve ese nombre, que suele incluir tu nombre o el modelo.",
                        "Cámbialo por uno genérico en Ajustes > Acerca del teléfono > Nombre del dispositivo.", "Bluetooth"
                    )
                )
            }
        }
        val emparejados = lista.filter { it.emparejado }
        if (emparejados.isNotEmpty()) {
            h.add(
                Hallazgo(
                    Riesgo.INFO, emparejados.size.toString() + " dispositivo(s) emparejado(s) con este teléfono",
                    emparejados.take(8).joinToString(", ") { it.nombreVisible } + (if (emparejados.size > 8) "…" else "") +
                        ". Un dispositivo emparejado puede conectarse solo, sin que lo notes.",
                    "Revisa la lista en Ajustes > Bluetooth y olvida los que no reconozcas o ya no uses.", "Bluetooth"
                )
            )
        }
        val conectables = lista.count { it.esBle && it.conectable == true && !it.emparejado }
        if (conectables >= 5) {
            h.add(
                Hallazgo(
                    Riesgo.INFO, conectables.toString() + " dispositivos BLE cercanos aceptan conexiones",
                    "Es lo habitual (relojes, auriculares, electrodomésticos). Cada uno es una superficie que depende de su propio firmware.",
                    "Nada que hacer; conviene saber qué hay a tu alrededor.", "Bluetooth"
                )
            )
        }
        val sinNombre = lista.count { it.nombre == null && it.alias == null && it.rastreador == null && !it.emparejado }
        if (sinNombre >= 8) {
            h.add(
                Hallazgo(
                    Riesgo.INFO, sinNombre.toString() + " dispositivos anónimos",
                    "No anuncian nombre. Es normal: muchos usan direcciones aleatorias que cambian con el tiempo.",
                    "Nada que hacer.", "Bluetooth"
                )
            )
        }

        h.sortBy { it.riesgo.ordinal }
        var puntos = 100
        for (x in h) puntos -= x.riesgo.peso
        puntos = puntos.coerceIn(0, 100)
        val veredicto = if (puntos >= 85) "Sin problemas relevantes" else if (puntos >= 65) "Revisa estos puntos" else "Hay riesgos importantes"
        return InformeBt(h, puntos, veredicto)
    }

    fun texto(res: ResultadoBt, informe: InformeBt): String {
        val sb = StringBuilder("Análisis Bluetooth · El Faro\n")
        sb.append(informe.puntuacion).append("/100 · ").append(informe.veredicto).append("\n\n")
        for (h in informe.hallazgos) {
            sb.append(h.riesgo.etiqueta.uppercase()).append(" · ").append(h.titulo).append('\n').append("  ").append(h.detalle).append('\n')
            if (h.riesgo != Riesgo.INFO) sb.append("  Qué hacer: ").append(h.accion).append('\n')
        }
        sb.append("\nDISPOSITIVOS (").append(res.dispositivos.size).append(")\n")
        for (x in res.dispositivos) {
            sb.append("• ").append(x.nombreVisible).append(" · ").append(x.direccion).append(" · ").append(x.tipoRadio)
            if (x.rssi != null) sb.append(" · ").append(x.rssi).append(" dBm")
            val f = Fabricantes.nombre(x.fabricanteId)
            if (f != null) sb.append(" · ").append(f)
            if (x.rastreador != null) sb.append(" · RASTREADOR: ").append(x.rastreador)
            sb.append('\n')
        }
        return sb.toString()
    }
}
