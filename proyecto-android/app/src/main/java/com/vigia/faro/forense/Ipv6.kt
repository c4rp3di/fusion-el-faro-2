package com.vigia.faro.forense

import android.content.Context
import android.net.ConnectivityManager
import com.vigia.faro.Dispositivo
import com.vigia.faro.Riesgo
import java.io.File
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.TimeUnit

/**
 * IPv6 en la red local: el barrido IPv4 no ve los equipos que solo hablan IPv6. Se envía un ping a «todos los equipos del enlace»
 * (ff02::1), se toma nota de quién contesta y, con ADB, se cruza con la tabla de vecinos para obtener su MAC y comprobar
 * qué router anuncia IPv6 (los anuncios falsos de router son un ataque clásico de intermediario).
 */
object Ipv6 {

    private val HEX_Y_DOS_PUNTOS = Regex("^[0-9a-fA-F:]+$")

    /** Si la dirección se formó a partir de la MAC (EUI-64), la devuelve. Los equipos con direcciones «de privacidad» no la revelan. */
    fun macDeEui64(ip: String): String? {
        val limpia = ip.substringBefore('%')
        if (!HEX_Y_DOS_PUNTOS.matches(limpia)) return null
        val b = try {
            InetAddress.getByName(limpia).address
        } catch (e: Exception) {
            return null
        }
        if (b.size != 16) return null
        if ((b[11].toInt() and 0xFF) != 0xFF || (b[12].toInt() and 0xFF) != 0xFE) return null
        val m = intArrayOf((b[8].toInt() and 0xFF) xor 0x02, b[9].toInt() and 0xFF, b[10].toInt() and 0xFF, b[13].toInt() and 0xFF, b[14].toInt() and 0xFF, b[15].toInt() and 0xFF)
        return m.joinToString(":") { String.format("%02x", it) }
    }

    fun nombreInterfaz(c: Context): String? {
        return try {
            val cm = c.getSystemService(ConnectivityManager::class.java)
            val red = cm.activeNetwork ?: return null
            cm.getLinkProperties(red)?.interfaceName
        } catch (e: Exception) {
            null
        }
    }

    /** Direcciones IPv6 «globales» del teléfono (alcanzables desde internet si el router no las filtra). */
    fun direccionesGlobales(c: Context): List<String> {
        val res = ArrayList<String>()
        try {
            val cm = c.getSystemService(ConnectivityManager::class.java)
            val red = cm.activeNetwork ?: return res
            val lp = cm.getLinkProperties(red) ?: return res
            for (la in lp.linkAddresses) {
                val a = la.address
                if (a !is Inet6Address) continue
                if (a.isLinkLocalAddress || a.isLoopbackAddress || a.isSiteLocalAddress || a.isMulticastAddress) continue
                val primero = a.address[0].toInt() and 0xFF
                if ((primero and 0xFE) == 0xFC) continue // fc00::/7, direcciones locales únicas
                res.add((a.hostAddress ?: continue).substringBefore('%'))
            }
        } catch (e: Exception) {
        }
        return res
    }

    /** Quién contesta a un ping a ff02::1 (todos los equipos del enlace). Lista vacía si el sistema no tiene ping para IPv6. */
    fun descubrir(interfaz: String?): List<String> {
        val orden = ArrayList<String>()
        if (File("/system/bin/ping6").exists()) {
            orden.add("/system/bin/ping6")
        } else if (File("/system/bin/ping").exists()) {
            orden.add("/system/bin/ping")
            orden.add("-6")
        } else {
            return emptyList()
        }
        orden.addAll(listOf("-c", "3", "-w", "4"))
        if (!interfaz.isNullOrEmpty()) {
            orden.add("-I")
            orden.add(interfaz)
        }
        orden.add("ff02::1")
        return try {
            val p = ProcessBuilder(orden).redirectErrorStream(true).start()
            val fin = p.waitFor(8, TimeUnit.SECONDS)
            if (!fin) p.destroy()
            val texto = p.inputStream.bufferedReader().readText()
            direccionesDeSalida(texto)
        } catch (e: Exception) {
            emptyList()
        }
    }

    private val DESDE = Regex("""bytes from ([0-9a-fA-F:]{3,45})(?:%[\w.-]+)?[:,]""")

    fun direccionesDeSalida(texto: String): List<String> {
        val res = LinkedHashSet<String>()
        for (m in DESDE.findAll(texto)) res.add(m.groupValues[1].lowercase())
        return res.toList()
    }

    /**
     * [respondieron]: direcciones IPv6 que contestaron al ping. [salidaAdb]: salida de ADB (puede ser null). [lista]: equipos del
     * barrido IPv4, a los que se les añaden sus direcciones IPv6.
     */
    fun analizar(
        datos: DatosForenses,
        respondieron: List<String>,
        globales: List<String>,
        salidaAdb: Map<String, String>?,
        lista: List<Dispositivo>,
        gateway: String?
    ) {
        val lineas = ArrayList<String>()
        if (globales.isNotEmpty()) {
            lineas.add("Direcciones IPv6 públicas de este teléfono: " + globales.take(3).joinToString(", "))
            datos.hallazgo(
                Riesgo.INFO, "Este teléfono tiene dirección IPv6 pública",
                "Con IPv6 no hay NAT: lo que impide que internet llegue a un equipo es el cortafuegos del router. Si el router no lo filtra, los equipos de la red podrían ser accesibles desde fuera.",
                "Comprueba que el cortafuegos IPv6 del router está activo (en su panel, sección IPv6 o Firewall).", "IPv6"
            )
        } else {
            lineas.add("Esta red no entrega direcciones IPv6 públicas al teléfono.")
        }

        // MAC de cada vecino IPv6 (ADB) y, si no, la que se deduce de la propia dirección (EUI-64).
        val vecinos6 = if (salidaAdb != null) ParserShell.vecinos(salidaAdb["vecinos6"] ?: "") else emptyList()
        val macDe = HashMap<String, String>()
        for (v in vecinos6) if (v.mac != null) macDe[v.ip.lowercase()] = v.mac
        val todas = LinkedHashSet<String>()
        todas.addAll(respondieron)
        for (v in vecinos6) if (v.mac != null && v.estado != "FAILED" && v.estado != "INCOMPLETE") todas.add(v.ip.lowercase())

        val macsIpv4 = lista.mapNotNull { it.mac }.toSet()
        val soloIpv6 = ArrayList<String>()
        for (ip in todas) {
            val mac = macDe[ip] ?: macDeEui64(ip)
            val equipo = if (mac != null) lista.firstOrNull { it.mac == mac } else null
            if (equipo != null) equipo.ipv6.add(ip)
            val fab = Oui.buscar(mac)
            lineas.add(
                ip + (if (mac != null) " → " + mac else "") + (if (fab != null) " (" + fab + ")" else "") +
                    (if (equipo != null) " = " + equipo.nombreVisible else "")
            )
            if (equipo == null && mac != null && !macsIpv4.contains(mac)) soloIpv6.add(ip)
        }
        if (todas.isEmpty()) lineas.add("Ningún equipo contestó por IPv6 (o el sistema no permite el ping IPv6).")
        datos.seccion("IPv6 en la red local (" + todas.size + ")", lineas)

        if (soloIpv6.isNotEmpty() && macsIpv4.isNotEmpty()) {
            datos.hallazgo(
                Riesgo.BAJO, soloIpv6.size.toString() + " equipo(s) visibles solo por IPv6",
                "No aparecieron en el barrido IPv4 pero contestan por IPv6: " + soloIpv6.take(4).joinToString(", ") + ". Un equipo que se oculta al barrido IPv4 merece identificarse.",
                "Compara sus direcciones con la lista de dispositivos del router.", "IPv6"
            )
        }

        // Quién anuncia IPv6 (routers): más de uno, o uno distinto del router IPv4, es sospechoso.
        if (salidaAdb != null) {
            val rutas = ParserShell.rutasDefecto6(salidaAdb["rutas"] ?: "").filter { it.protocolo == "ra" || it.protocolo.isEmpty() }
            val routers = rutas.map { it.via.lowercase() }.distinct()
            if (routers.size >= 2) {
                datos.hallazgo(
                    Riesgo.MEDIO, routers.size.toString() + " equipos se anuncian como router IPv6",
                    "Se anuncian como puerta de salida: " + routers.joinToString(", ") + ". Es normal con redes mesh o dos routers; también es un ataque (anuncios de router falsos) que desvía todo el tráfico IPv6.",
                    "Comprueba que todos son tuyos. Si no, desactiva IPv6 en el router o avisa al administrador.", "IPv6"
                )
            }
            val macGw4 = if (gateway != null) lista.firstOrNull { it.ip == gateway }?.mac else null
            if (macGw4 != null) {
                for (r in routers) {
                    val m = macDe[r] ?: macDeEui64(r)
                    if (m != null && m != macGw4) {
                        datos.hallazgo(
                            Riesgo.MEDIO, "El router IPv6 (" + r + ") no es tu router IPv4",
                            "Su MAC es " + m + " y la de tu router es " + macGw4 + ". Puede ser un segundo router o repetidor legítimo, o un equipo que se anuncia como router para interceptar el tráfico IPv6.",
                            "Identifica ese equipo en la lista de dispositivos del router.", "IPv6"
                        )
                    }
                }
            }
            if (routers.isNotEmpty()) datos.seccion("Routers IPv6 anunciados", routers.map { it + " (MAC " + (macDe[it] ?: macDeEui64(it) ?: "?") + ")" })
        }
    }
}
