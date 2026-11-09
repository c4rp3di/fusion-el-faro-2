package com.vigia.faro.forense

import com.vigia.core.red.UtilRed
import com.vigia.faro.Riesgo
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.Random

/**
 * Comprobaciones de DNS: respuestas falsas (dirección privada para una web pública), interceptación del DNS por la red
 * y «secuestro de NXDOMAIN» (la red inventa una respuesta para un dominio que no existe).
 */
object SondaDns {

    class RespuestaDns(val rcode: Int, val ips: List<String>)

    fun consulta(nombre: String, id: Int): ByteArray {
        val b = ByteArrayOutputStream()
        b.write(id shr 8)
        b.write(id and 0xFF)
        b.write(0x01)
        b.write(0x00)
        b.write(0)
        b.write(1)
        for (i in 0 until 6) b.write(0)
        for (etiqueta in nombre.split('.')) {
            val bytes = etiqueta.toByteArray(Charsets.US_ASCII)
            b.write(bytes.size)
            b.write(bytes, 0, bytes.size)
        }
        b.write(0)
        b.write(0)
        b.write(1)
        b.write(0)
        b.write(1)
        return b.toByteArray()
    }

    private fun u16(d: ByteArray, p: Int): Int = ((d[p].toInt() and 0xFF) shl 8) or (d[p + 1].toInt() and 0xFF)

    private fun saltarNombre(d: ByteArray, n: Int, inicio: Int): Int {
        var p = inicio
        while (true) {
            if (p >= n) return -1
            val l = d[p].toInt() and 0xFF
            if (l == 0) return p + 1
            if ((l and 0xC0) == 0xC0) return p + 2
            p += l + 1
        }
    }

    fun leer(d: ByteArray, n: Int, idEsperado: Int): RespuestaDns? {
        if (n < 12) return null
        if (u16(d, 0) != idEsperado) return null
        val flags = u16(d, 2)
        if ((flags and 0x8000) == 0) return null
        val rcode = flags and 0x0F
        val qd = u16(d, 4)
        val an = u16(d, 6)
        var p = 12
        for (i in 0 until qd) {
            p = saltarNombre(d, n, p)
            if (p < 0) return null
            p += 4
        }
        val ips = ArrayList<String>()
        for (i in 0 until an) {
            p = saltarNombre(d, n, p)
            if (p < 0 || p + 10 > n) break
            val tipo = u16(d, p)
            val largo = u16(d, p + 8)
            p += 10
            if (p + largo > n) break
            if (tipo == 1 && largo == 4) {
                ips.add((d[p].toInt() and 0xFF).toString() + "." + (d[p + 1].toInt() and 0xFF) + "." + (d[p + 2].toInt() and 0xFF) + "." + (d[p + 3].toInt() and 0xFF))
            }
            p += largo
        }
        return RespuestaDns(rcode, ips)
    }

    /** Una consulta A por UDP directa a [servidor]. Devuelve null si no contestó. */
    fun preguntar(servidor: String, nombre: String, timeoutMs: Int): RespuestaDns? {
        val id = Random().nextInt(0xFFFF)
        val q = consulta(nombre, id)
        val s = DatagramSocket()
        return try {
            s.soTimeout = timeoutMs
            s.send(DatagramPacket(q, q.size, InetAddress.getByName(servidor), 53))
            val buf = ByteArray(1500)
            val r = DatagramPacket(buf, buf.size)
            s.receive(r)
            leer(buf, r.length, id)
        } catch (e: Exception) {
            null
        } finally {
            s.close()
        }
    }

    private fun sistema(nombre: String): List<String>? {
        return try {
            InetAddress.getAllByName(nombre).filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress }
        } catch (e: Exception) {
            null
        }
    }

    private fun sospechosa(ip: String): Boolean {
        val n = UtilRed.parseIpv4(ip) ?: return false
        return UtilRed.esIpPrivada(n) || ip == "0.0.0.0"
    }

    private val DOMINIOS = listOf("www.google.com", "www.wikipedia.org", "www.cloudflare.com")

    fun analizar(datos: DatosForenses, dnsDeLaRed: List<String>) {
        val lineas = ArrayList<String>()
        var publicosRespondieron = false
        for (d in DOMINIOS) {
            val sis = sistema(d)
            val cf = preguntar("1.1.1.1", d, 2000)
            val gg = preguntar("8.8.8.8", d, 2000)
            if (cf != null || gg != null) publicosRespondieron = true
            lineas.add(
                d + ": sistema " + (sis?.joinToString(",") ?: "sin respuesta") + " · 1.1.1.1 " + (cf?.ips?.joinToString(",") ?: "sin respuesta") +
                    " · 8.8.8.8 " + (gg?.ips?.joinToString(",") ?: "sin respuesta")
            )
            val publicas = (cf?.ips ?: emptyList()) + (gg?.ips ?: emptyList())
            if (sis != null && sis.any { sospechosa(it) } && publicas.isNotEmpty() && publicas.none { sospechosa(it) }) {
                datos.hallazgo(
                    Riesgo.ALTO, "El DNS de la red da una dirección privada para " + d,
                    "El sistema resuelve " + d + " como " + sis.joinToString(", ") + ", pero los DNS públicos dan " + publicas.distinct().joinToString(", ") + ". Es la señal de un DNS manipulado (redirige tus visitas a otro equipo).",
                    "No inicies sesión en ninguna web en esta red. Cambia el DNS del router (1.1.1.1 o 9.9.9.9) y revisa el router.", "DNS"
                )
            }
            if (publicas.any { sospechosa(it) }) {
                datos.hallazgo(
                    Riesgo.ALTO, "Un DNS público devolvió una dirección privada para " + d,
                    "Los DNS públicos nunca deberían dar direcciones privadas para webs reales: la red está alterando las respuestas en el camino.",
                    "Evita esta red o usa una VPN.", "DNS"
                )
            }
        }
        if (!publicosRespondieron) {
            lineas.add("Los DNS públicos (1.1.1.1 y 8.8.8.8) no contestaron por UDP directo: la red los bloquea o los redirige.")
            datos.hallazgo(
                Riesgo.INFO, "La red bloquea las consultas DNS a servidores públicos",
                "Es habitual en redes de empresa y portales cautivos, y impide comprobar el DNS por esa vía.",
                "Nada que hacer.", "DNS"
            )
        }

        // Interceptación: una dirección de documentación (192.0.2.0/24) no debería contestar nunca.
        val intercepta = preguntar("192.0.2.53", "www.google.com", 1500)
        if (intercepta != null) {
            lineas.add("Se respondió desde 192.0.2.53, que no existe: el DNS está siendo interceptado.")
            datos.hallazgo(
                Riesgo.ALTO, "La red intercepta el DNS",
                "Una consulta a una dirección que no es un servidor DNS recibió respuesta: algún equipo de la red contesta a todas las consultas DNS, así que puede decidir adónde te lleva cada nombre.",
                "Usa DNS privado (cifrado) o una VPN. Si es tu red, revisa la configuración del router.", "DNS"
            )
        } else {
            lineas.add("Sin interceptación del DNS (prueba a una dirección inexistente).")
        }

        // Secuestro de NXDOMAIN.
        val azar = StringBuilder("faro-")
        val r = Random()
        for (i in 0 until 14) azar.append(('a' + r.nextInt(26)))
        val inexistente = azar.toString() + ".com"
        val resp = sistema(inexistente)
        if (resp != null && resp.isNotEmpty()) {
            lineas.add("Dominio inexistente resuelto como " + resp.joinToString(","))
            datos.hallazgo(
                Riesgo.MEDIO, "El DNS inventa respuestas para dominios que no existen",
                "Un dominio inexistente se resolvió como " + resp.joinToString(", ") + ". Algunos operadores lo hacen para mostrar publicidad; también lo hace quien redirige el tráfico.",
                "Usa un DNS que no manipule respuestas (1.1.1.1, 9.9.9.9) o DNS privado.", "DNS"
            )
        } else {
            lineas.add("Los dominios inexistentes dan error, como debe ser.")
        }

        // DNS que entrega la red, preguntado directamente.
        for (s in dnsDeLaRed) {
            if (UtilRed.parseIpv4(s) == null) continue
            val r1 = preguntar(s, "www.google.com", 2000)
            lineas.add("DNS de la red " + s + ": " + (if (r1 == null) "no contesta por UDP" else r1.ips.joinToString(",").ifEmpty { "sin direcciones (código " + r1.rcode + ")" }))
        }
        datos.seccion("DNS", lineas)
    }
}
