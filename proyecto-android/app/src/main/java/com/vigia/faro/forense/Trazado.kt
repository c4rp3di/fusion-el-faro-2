package com.vigia.faro.forense

import com.vigia.core.red.UtilRed
import com.vigia.faro.Riesgo
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Traza corta hacia internet con el comando `ping` del sistema variando el TTL: el primer salto debe ser el router. Si no
 * lo es, hay un equipo intermedio; si el segundo es privado o 100.64/10, la conexión pasa por un doble NAT (CGNAT).
 */
object Trazado {

    class Salto(val ttl: Int, val ip: String?, val llego: Boolean)

    private val DESDE = Regex("""(?:[Ff]rom|desde)\s+(\d{1,3}(?:\.\d{1,3}){3})""")

    private fun salto(destino: String, ttl: Int): Salto {
        return try {
            val p = ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "2", "-t", ttl.toString(), destino).redirectErrorStream(true).start()
            val fin = p.waitFor(5, TimeUnit.SECONDS)
            if (!fin) {
                p.destroy()
                return Salto(ttl, null, false)
            }
            val texto = p.inputStream.bufferedReader().readText()
            p.destroy()
            val ip = DESDE.find(texto)?.groupValues?.get(1)
            val llego = texto.contains("bytes from") || texto.contains("ttl=")
            if (llego) Salto(ttl, destino, true) else Salto(ttl, ip, false)
        } catch (e: Exception) {
            Salto(ttl, null, false)
        }
    }

    private fun esCgnat(ip: String): Boolean {
        val n = UtilRed.parseIpv4(ip) ?: return false
        val a = (n ushr 24) and 0xFF
        val b = (n ushr 16) and 0xFF
        return a == 100 && b in 64..127
    }

    fun analizar(datos: DatosForenses, gateway: String?) {
        if (!File("/system/bin/ping").exists()) {
            datos.limitaciones.add("No hay comando ping en el sistema: no se hizo la traza hacia internet.")
            return
        }
        val saltos = ArrayList<Salto>()
        for (ttl in 1..4) {
            val s = salto("1.1.1.1", ttl)
            saltos.add(s)
            if (s.llego) break
        }
        val lineas = saltos.map { "Salto " + it.ttl + ": " + (it.ip ?: "sin respuesta") + (if (it.llego) " (destino)" else "") }
        datos.seccion("Ruta hacia internet", lineas)

        val primero = saltos.firstOrNull()?.ip
        if (gateway != null && primero != null && primero != gateway) {
            datos.hallazgo(
                Riesgo.MEDIO, "El primer salto hacia internet no es tu router (" + primero + " en vez de " + gateway + ")",
                "Entre el teléfono y el router hay otro equipo que reenvía el tráfico. Es normal con algunos repetidores y routers en cascada; también es lo que haría un equipo que intercepta el tráfico.",
                "Comprueba qué equipo es " + primero + " (lista de dispositivos del router).", "Traza"
            )
        }
        val segundo = saltos.getOrNull(1)?.ip
        if (segundo != null) {
            val n = UtilRed.parseIpv4(segundo)
            if (esCgnat(segundo)) {
                datos.hallazgo(
                    Riesgo.INFO, "Tu operador usa CGNAT (100.64.0.0/10)",
                    "Compartes dirección pública con otros clientes: desde internet no se puede llegar a tu red directamente, lo que es bueno para la seguridad.",
                    "Nada que hacer.", "Traza"
                )
            } else if (n != null && UtilRed.esIpPrivada(n)) {
                datos.hallazgo(
                    Riesgo.INFO, "Doble NAT: hay otro router detrás del tuyo (" + segundo + ")",
                    "Tu router está conectado a otro equipo de red privada (el del operador o un segundo router). Reduce la exposición, pero complica ver quién controla qué.",
                    "Si no lo esperabas, revisa cómo está conectado tu router.", "Traza"
                )
            }
        }
    }
}
