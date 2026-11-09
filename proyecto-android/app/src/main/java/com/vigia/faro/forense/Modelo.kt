package com.vigia.faro.forense

import com.vigia.faro.Hallazgo
import com.vigia.faro.Riesgo
import java.security.MessageDigest

/** Un bloque de texto del informe forense (por ejemplo «Teléfono» o «Conexiones del teléfono»). */
class Seccion(val titulo: String, val lineas: List<String>)

object Huellas {
    fun sha256(datos: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(datos)
        val sb = StringBuilder(d.size * 2)
        for (b in d) sb.append(String.format("%02x", b.toInt() and 0xFF))
        return sb.toString()
    }

    fun sha256(texto: String): String = sha256(texto.toByteArray(Charsets.UTF_8))
}

/**
 * Una salida cruda guardada como prueba (por ejemplo lo que devolvió `ip neigh`). El hash se calcula sobre el contenido
 * ya guardado, así que quien reciba el paquete de evidencia puede recalcularlo y comprobar que no se tocó.
 */
class Artefacto(
    val id: String,
    val orden: String,
    val momento: Long,
    val contenido: String,
    val truncado: Boolean,
    val bytesOriginales: Int
) {
    val sha256: String = Huellas.sha256(contenido)

    companion object {
        private const val MAX_CARACTERES = 120_000

        fun crear(id: String, orden: String, salida: String): Artefacto {
            val truncado = salida.length > MAX_CARACTERES
            val c = if (truncado) salida.substring(0, MAX_CARACTERES) else salida
            return Artefacto(id, orden, System.currentTimeMillis(), c, truncado, salida.length)
        }
    }
}

/** Todo lo que averigua la parte forense en un análisis. Cada módulo añade aquí sus hallazgos, secciones y pruebas. */
class DatosForenses {
    val hallazgos = ArrayList<Hallazgo>()
    val secciones = ArrayList<Seccion>()
    val artefactos = ArrayList<Artefacto>()
    var adbUsado = false
    var indicadoresCargados = 0

    /** Mensajes sobre lo que no se pudo comprobar (para no dar una falsa sensación de limpieza). */
    val limitaciones = ArrayList<String>()

    fun hallazgo(riesgo: Riesgo, titulo: String, detalle: String, accion: String, fuente: String) {
        hallazgos.add(Hallazgo(riesgo, titulo, detalle, accion, fuente))
    }

    fun seccion(titulo: String, lineas: List<String>) {
        if (lineas.isNotEmpty()) secciones.add(Seccion(titulo, lineas))
    }

    /** Incorpora lo de otro conjunto de datos (se usa para juntar los resultados de comprobaciones que corren en paralelo). */
    fun anadir(otros: DatosForenses) {
        hallazgos.addAll(otros.hallazgos)
        secciones.addAll(otros.secciones)
        artefactos.addAll(otros.artefactos)
        limitaciones.addAll(otros.limitaciones)
    }

    fun artefacto(id: String, orden: String, salida: String) {
        artefactos.add(Artefacto.crear(id, orden, salida))
    }
}
