package com.vigia.faro.forense

/**
 * Lectores de la salida de las órdenes del shell (ip, cmd wifi, getprop, /proc/net…). Son funciones puras y tolerantes:
 * el formato cambia entre versiones y fabricantes, así que lo que no se entiende se ignora en vez de fallar.
 */
object ParserShell {

    private val MAC = Regex("""^[0-9a-f]{2}(:[0-9a-f]{2}){5}$""")

    fun esMac(t: String): Boolean = MAC.matches(t.lowercase())

    // ------------------------------------------------------------------ ip neigh

    class Vecino(val ip: String, val interfaz: String, val mac: String?, val estado: String)

    private val ESTADOS_VECINO = setOf("REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE", "PERMANENT", "NOARP", "NONE")

    fun vecinos(texto: String): List<Vecino> {
        val res = ArrayList<Vecino>()
        for (linea in texto.lines()) {
            val t = linea.trim().split(Regex("\\s+"))
            if (t.size < 3) continue
            val ip = t[0]
            if (!ip.contains('.') && !ip.contains(':')) continue
            val iDev = t.indexOf("dev")
            if (iDev < 0 || iDev + 1 >= t.size) continue
            val iMac = t.indexOf("lladdr")
            val mac = if (iMac >= 0 && iMac + 1 < t.size) t[iMac + 1].lowercase() else null
            val estado = t.lastOrNull { ESTADOS_VECINO.contains(it) } ?: ""
            res.add(Vecino(ip, t[iDev + 1], if (mac != null && esMac(mac)) mac else null, estado))
        }
        return res
    }

    // ------------------------------------------------------------------ Wi-Fi

    class EstadoWifi(
        val ssid: String?,
        val bssid: String?,
        val tipoSeguridad: Int?,
        val frecuenciaMhz: Int?,
        val rssi: Int?,
        val velocidadMbps: Int?,
        val estandar: Int?
    )

    fun wifiEstado(texto: String): EstadoWifi? {
        val bssid = Regex("""BSSID: ([0-9a-fA-F:]{17})""").find(texto)?.groupValues?.get(1)?.lowercase()
        val ssid = Regex("\\bSSID: \"([^\"]*)\"").find(texto)?.groupValues?.get(1)
        if (bssid == null && ssid == null) return null
        fun entero(patron: String): Int? = Regex(patron).find(texto)?.groupValues?.get(1)?.toIntOrNull()
        return EstadoWifi(
            ssid = ssid,
            bssid = bssid,
            tipoSeguridad = entero("""Security type: (-?\d+)"""),
            frecuenciaMhz = entero("""Frequency: (\d+)\s*MHz"""),
            rssi = entero("""RSSI: (-?\d+)"""),
            velocidadMbps = entero("""(?<!Tx |Rx |Max Supported Tx |Max Supported Rx )Link speed: (\d+)"""),
            estandar = entero("""Wi-Fi standard: (\d+)""")
        )
    }

    class PuntoAcceso(val bssid: String, val frecuencia: Int, val rssi: Int, val ssid: String, val flags: String)

    private val EDAD = Regex("""^\d+\.\d+$""")

    fun escaneo(texto: String): List<PuntoAcceso> {
        val res = ArrayList<PuntoAcceso>()
        for (linea in texto.lines()) {
            val p = linea.trim().split(Regex("\\s+"))
            if (p.size < 3) continue
            val bssid = p[0].lowercase()
            if (!esMac(bssid)) continue
            val f = p[1].toIntOrNull() ?: continue
            val r = p[2].toIntOrNull() ?: continue
            var resto = p.drop(3)
            if (resto.isNotEmpty() && EDAD.matches(resto[0])) resto = resto.drop(1)
            val unido = resto.joinToString(" ")
            val i = unido.indexOf('[')
            val ssid = if (i >= 0) unido.substring(0, i).trim() else unido.trim()
            val flags = if (i >= 0) unido.substring(i).trim() else ""
            res.add(PuntoAcceso(bssid, f, r, ssid, flags))
        }
        return res
    }

    /** ABIERTA, WEP, WPA, WPA2, WPA3, OWE o EMPRESA según las «capabilities» de un punto de acceso. */
    fun claseSeguridad(flags: String): String {
        return when {
            flags.contains("EAP") -> "EMPRESA"
            flags.contains("SAE") -> "WPA3"
            flags.contains("OWE") -> "OWE"
            flags.contains("WEP") -> "WEP"
            flags.contains("WPA2") || flags.contains("RSN") -> "WPA2"
            flags.contains("WPA") -> "WPA"
            else -> "ABIERTA"
        }
    }

    fun esDebil(clase: String): Boolean = clase == "ABIERTA" || clase == "WEP" || clase == "WPA"

    fun canal(frecuenciaMhz: Int): Int {
        return when {
            frecuenciaMhz == 2484 -> 14
            frecuenciaMhz in 2412..2472 -> (frecuenciaMhz - 2407) / 5
            frecuenciaMhz in 5160..5885 -> (frecuenciaMhz - 5000) / 5
            frecuenciaMhz >= 5955 -> (frecuenciaMhz - 5950) / 5
            else -> 0
        }
    }

    fun banda(frecuenciaMhz: Int): String {
        return when {
            frecuenciaMhz in 2400..2500 -> "2,4 GHz"
            frecuenciaMhz in 5150..5900 -> "5 GHz"
            frecuenciaMhz >= 5925 -> "6 GHz"
            else -> "?"
        }
    }

    class RedGuardada(val ssid: String, val seguridad: String)

    fun redesGuardadas(texto: String): List<RedGuardada> {
        val res = ArrayList<RedGuardada>()
        val patron = Regex("""^\s*(\d+)\s+(.+?)\s{2,}(\S+)\s*$""")
        for (linea in texto.lines()) {
            val m = patron.find(linea) ?: continue
            res.add(RedGuardada(m.groupValues[2].trim(), m.groupValues[3].lowercase()))
        }
        return res
    }

    // ------------------------------------------------------------------ /proc/net/tcp, udp

    class Conexion(
        val protocolo: String,
        val localIp: String,
        val localPuerto: Int,
        val remotoIp: String,
        val remotoPuerto: Int,
        val estado: Int,
        val uid: Int
    ) {
        val escuchando: Boolean get() = if (protocolo.startsWith("tcp")) estado == 0x0A else (remotoPuerto == 0)
        val establecida: Boolean get() = protocolo.startsWith("tcp") && estado == 0x01
    }

    /** «0100007F» (little-endian, como lo escribe el kernel) → «127.0.0.1». */
    fun ipv4Hex(h: String): String {
        val v = h.toLong(16)
        return (v and 0xFF).toString() + "." + ((v shr 8) and 0xFF) + "." + ((v shr 16) and 0xFF) + "." + ((v shr 24) and 0xFF)
    }

    /** Dirección de 32 caracteres hexadecimales (cuatro palabras little-endian). Las IPv4 «mapeadas» se devuelven como IPv4. */
    fun ipv6Hex(h: String): String {
        val b = ArrayList<Int>(16)
        for (i in 0 until 4) {
            val w = h.substring(i * 8, i * 8 + 8)
            b.add(w.substring(6, 8).toInt(16))
            b.add(w.substring(4, 6).toInt(16))
            b.add(w.substring(2, 4).toInt(16))
            b.add(w.substring(0, 2).toInt(16))
        }
        val ceros10 = (0 until 10).all { b[it] == 0 }
        if (ceros10 && b[10] == 0xFF && b[11] == 0xFF) return b[12].toString() + "." + b[13] + "." + b[14] + "." + b[15]
        if (b.all { it == 0 }) return "::"
        if ((0 until 15).all { b[it] == 0 } && b[15] == 1) return "::1"
        val grupos = ArrayList<String>()
        for (i in 0 until 8) grupos.add(String.format("%02x%02x", b[i * 2], b[i * 2 + 1]))
        return grupos.joinToString(":")
    }

    private fun direccion(h: String): Pair<String, Int>? {
        val i = h.indexOf(':')
        if (i <= 0) return null
        val ip = h.substring(0, i)
        val puerto = h.substring(i + 1).toIntOrNull(16) ?: return null
        return when (ip.length) {
            8 -> Pair(ipv4Hex(ip), puerto)
            32 -> Pair(ipv6Hex(ip), puerto)
            else -> null
        }
    }

    fun conexiones(texto: String, protocolo: String): List<Conexion> {
        val res = ArrayList<Conexion>()
        for (linea in texto.lines()) {
            val t = linea.trim().split(Regex("\\s+"))
            if (t.size < 8 || !t[0].endsWith(":")) continue
            if (t[0].dropLast(1).toIntOrNull() == null) continue
            val l = try { direccion(t[1]) } catch (e: Exception) { null } ?: continue
            val r = try { direccion(t[2]) } catch (e: Exception) { null } ?: continue
            val estado = t[3].toIntOrNull(16) ?: continue
            val uid = t[7].toIntOrNull() ?: continue
            res.add(Conexion(protocolo, l.first, l.second, r.first, r.second, estado, uid))
        }
        return res
    }

    // ------------------------------------------------------------------ getprop y ajustes

    fun propiedades(texto: String): Map<String, String> {
        val res = HashMap<String, String>()
        val patron = Regex("""^\[(.+?)\]: \[(.*)\]$""")
        for (linea in texto.lines()) {
            val m = patron.find(linea.trim()) ?: continue
            res[m.groupValues[1]] = m.groupValues[2]
        }
        return res
    }

    /** `settings get` imprime «null» cuando el ajuste no existe. */
    fun ajuste(texto: String?): String? {
        val t = texto?.trim() ?: return null
        if (t.isEmpty() || t == "null" || t.startsWith("Error") || t.contains("Exception") || t.contains("not found")) return null
        return t
    }

    // ------------------------------------------------------------------ administración del dispositivo

    class Propietario(val tipo: String, val paquete: String)

    /** Busca «Device Owner» y «Profile Owner» en `dumpsys device_policy` y el paquete de su administrador. */
    fun propietarios(texto: String): List<Propietario> {
        val res = ArrayList<Propietario>()
        val lineas = texto.lines()
        val admin = Regex("""admin=ComponentInfo\{([^/}]+)/""")
        var i = 0
        while (i < lineas.size) {
            val l = lineas[i].trim()
            val tipo = when {
                l.startsWith("Device Owner") -> "Propietario del dispositivo"
                l.startsWith("Profile Owner") -> "Propietario del perfil"
                else -> null
            }
            if (tipo != null) {
                var j = i
                while (j < lineas.size && j <= i + 5) {
                    val m = admin.find(lineas[j])
                    if (m != null) {
                        res.add(Propietario(tipo, m.groupValues[1]))
                        break
                    }
                    j++
                }
            }
            i++
        }
        return res
    }

    // ------------------------------------------------------------------ apps (dumpsys package y appops)

    class DetallePaquete(
        val permisosConcedidos: List<String>,
        val primeraInstalacion: String?,
        val ultimaActualizacion: String?,
        val instalador: String?
    )

    fun detallePaquete(texto: String): DetallePaquete {
        val permisos = LinkedHashSet<String>()
        val patron = Regex("""^\s*([A-Za-z0-9_.]+): granted=true""")
        for (linea in texto.lines()) {
            val m = patron.find(linea) ?: continue
            permisos.add(m.groupValues[1])
        }
        fun campo(nombre: String): String? =
            Regex(nombre + """=([^\r\n]+)""").find(texto)?.groupValues?.get(1)?.trim()
        return DetallePaquete(permisos.toList(), campo("firstInstallTime"), campo("lastUpdateTime"), campo("installerPackageName"))
    }

    class UsoOp(val op: String, val modo: String, val haceMs: Long?)

    /** «1d2h3m4s500ms» → milisegundos. */
    fun duracionMs(t: String): Long? {
        var total = 0L
        var alguno = false
        for (m in Regex("(\\d+)(ms|d|h|m|s)").findAll(t)) {
            val n = m.groupValues[1].toLongOrNull() ?: continue
            alguno = true
            total += when (m.groupValues[2]) {
                "d" -> n * 86_400_000L
                "h" -> n * 3_600_000L
                "m" -> n * 60_000L
                "s" -> n * 1_000L
                else -> n
            }
        }
        return if (alguno) total else null
    }

    fun appops(texto: String): List<UsoOp> {
        val res = ArrayList<UsoOp>()
        val nombre = Regex("^[A-Z][A-Z_0-9]+$")
        val tiempo = Regex("""time=\+([0-9a-z]+) ago""")
        for (linea in texto.lines()) {
            val l = linea.trim()
            val i = l.indexOf(':')
            if (i <= 0) continue
            val op = l.substring(0, i).trim()
            if (!nombre.matches(op)) continue
            val resto = l.substring(i + 1)
            val modo = resto.split(';')[0].trim()
            val ms = tiempo.find(resto)?.groupValues?.get(1)?.let { duracionMs(it) }
            res.add(UsoOp(op, modo, ms))
        }
        return res
    }

    // ------------------------------------------------------------------ varios

    /** Líneas de `ls -l` que corresponden a un archivo que existe (no «No such file» ni «Permission denied»). */
    fun existentes(texto: String): List<String> {
        val res = ArrayList<String>()
        for (linea in texto.lines()) {
            val l = linea.trim()
            if (l.isEmpty()) continue
            if (l.contains("No such file") || l.contains("Permission denied") || l.contains("not found")) continue
            if (l.startsWith("-") || l.startsWith("l") || l.startsWith("d")) res.add(l)
        }
        return res
    }
}
