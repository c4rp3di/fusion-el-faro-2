package com.vigia.faro

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket

enum class Riesgo(val peso: Int, val etiqueta: String) {
    CRITICO(30, "Crítico"),
    ALTO(15, "Alto"),
    MEDIO(7, "Medio"),
    BAJO(3, "Bajo"),
    INFO(0, "Info")
}

class PuertoDef(val puerto: Int, val servicio: String, val riesgo: Riesgo, val nota: String)

class PuertoAbierto(val def: PuertoDef, val banner: String?, val redirigeAHttps: Boolean)

/** Puertos que se comprueban: los que más se explotan en routers, cámaras y dispositivos domésticos. */
object CatalogoPuertos {
    val TODOS: List<PuertoDef> = listOf(
        PuertoDef(21, "FTP", Riesgo.ALTO, "Transfiere archivos y contraseñas sin cifrar."),
        PuertoDef(22, "SSH", Riesgo.BAJO, "Acceso remoto cifrado. Aceptable si la contraseña es fuerte y no es la de fábrica."),
        PuertoDef(23, "Telnet", Riesgo.CRITICO, "Acceso remoto SIN cifrar y blanco habitual de malware como Mirai."),
        PuertoDef(53, "DNS", Riesgo.INFO, "Servidor DNS."),
        PuertoDef(80, "HTTP", Riesgo.MEDIO, "Panel web sin cifrar: la contraseña viaja en claro por la red."),
        PuertoDef(139, "NetBIOS", Riesgo.MEDIO, "Compartición de archivos antigua de Windows."),
        PuertoDef(443, "HTTPS", Riesgo.INFO, "Panel web cifrado."),
        PuertoDef(445, "SMB", Riesgo.MEDIO, "Compartición de archivos de Windows; histórico objetivo de ransomware."),
        PuertoDef(515, "LPD", Riesgo.BAJO, "Servicio de impresión antiguo."),
        PuertoDef(554, "RTSP", Riesgo.MEDIO, "Vídeo de cámara: suele emitirse sin cifrar y a veces sin contraseña."),
        PuertoDef(631, "IPP", Riesgo.INFO, "Impresión en red."),
        PuertoDef(1723, "PPTP", Riesgo.ALTO, "VPN obsoleta con cifrado roto."),
        PuertoDef(2323, "Telnet alt.", Riesgo.CRITICO, "Telnet en puerto alternativo, igual de peligroso."),
        PuertoDef(3389, "RDP", Riesgo.ALTO, "Escritorio remoto de Windows."),
        PuertoDef(5000, "UPnP/Web", Riesgo.INFO, "Interfaz web habitual de NAS y servicios UPnP."),
        PuertoDef(5555, "ADB", Riesgo.CRITICO, "Depuración de Android abierta en la red: cualquiera en el Wi-Fi podría controlar el dispositivo."),
        PuertoDef(5900, "VNC", Riesgo.ALTO, "Escritorio remoto, a menudo con contraseña débil o ninguna."),
        PuertoDef(7547, "TR-069", Riesgo.MEDIO, "Gestión remota del operador; ha tenido fallos graves."),
        PuertoDef(8000, "HTTP alt.", Riesgo.MEDIO, "Panel web sin cifrar en puerto alternativo."),
        PuertoDef(8008, "Cast", Riesgo.INFO, "Chromecast / Google TV."),
        PuertoDef(8009, "Cast", Riesgo.INFO, "Chromecast / Google TV."),
        PuertoDef(8080, "HTTP alt.", Riesgo.MEDIO, "Panel web sin cifrar en puerto alternativo."),
        PuertoDef(8291, "Winbox", Riesgo.MEDIO, "Administración de routers MikroTik."),
        PuertoDef(8443, "HTTPS alt.", Riesgo.INFO, "Panel web cifrado en puerto alternativo."),
        PuertoDef(9100, "Impresora", Riesgo.MEDIO, "Impresión directa sin autenticación."),
        PuertoDef(37215, "UPnP-Huawei", Riesgo.ALTO, "Puerto asociado a fallos graves en routers Huawei."),
        PuertoDef(49152, "UPnP", Riesgo.INFO, "Servicio UPnP."),
        PuertoDef(62078, "iOS", Riesgo.INFO, "Servicio de sincronización de iPhone/iPad.")
    )

    private val HTTP = setOf(80, 8000, 8008, 8080, 5000)
    private val BANNER = setOf(21, 22, 23, 2323, 5555, 5900)

    fun esHttp(p: Int): Boolean = HTTP.contains(p)

    fun daBanner(p: Int): Boolean = BANNER.contains(p)
}

/** Resultado de un intento de conexión TCP. */
enum class SondeoTcp { ABIERTO, CERRADO, SIN_RESPUESTA }

object EscanerPuertos {

    /** Una conexión TCP: ABIERTO, CERRADO (rechazada: el equipo está vivo) o SIN_RESPUESTA (tiempo agotado o inalcanzable). */
    fun sondear(ip: String, puerto: Int, timeoutMs: Int): SondeoTcp {
        val s = Socket()
        return try {
            s.connect(InetSocketAddress(ip, puerto), timeoutMs)
            SondeoTcp.ABIERTO
        } catch (e: ConnectException) {
            if ((e.message ?: "").contains("refused", ignoreCase = true)) SondeoTcp.CERRADO else SondeoTcp.SIN_RESPUESTA
        } catch (e: Exception) {
            SondeoTcp.SIN_RESPUESTA
        } finally {
            try {
                s.close()
            } catch (e: Exception) {
            }
        }
    }

    suspend fun escanear(
        ip: String,
        defs: List<PuertoDef> = CatalogoPuertos.TODOS,
        concurrencia: Int = 16,
        timeoutMs: Int = 700
    ): List<PuertoAbierto> = coroutineScope {
        val sem = Semaphore(concurrencia)
        defs.map { d -> async(Dispatchers.IO) { sem.withPermit { abierto(ip, d, timeoutMs) } } }
            .awaitAll()
            .filterNotNull()
            .sortedBy { it.def.puerto }
    }

    private fun abierto(ip: String, d: PuertoDef, timeoutMs: Int): PuertoAbierto? {
        val s = Socket()
        try {
            s.connect(InetSocketAddress(ip, d.puerto), timeoutMs)
        } catch (e: Exception) {
            try {
                s.close()
            } catch (e2: Exception) {
            }
            return null
        }
        var banner: String? = null
        var https = false
        try {
            s.soTimeout = 800
            if (CatalogoPuertos.esHttp(d.puerto)) {
                val peticion = "HEAD / HTTP/1.0\r\nHost: " + ip + "\r\nUser-Agent: Faro\r\nConnection: close\r\n\r\n"
                s.getOutputStream().write(peticion.toByteArray(Charsets.US_ASCII))
                s.getOutputStream().flush()
                val texto = leer(s, 1200)
                val resultado = ParserHttp.analizar(texto)
                banner = resultado.resumen
                https = resultado.redirigeAHttps
            } else if (CatalogoPuertos.daBanner(d.puerto)) {
                banner = limpiar(leer(s, 160))
            }
        } catch (e: Exception) {
            // Sin banner: el puerto sigue contando como abierto.
        } finally {
            try {
                s.close()
            } catch (e: Exception) {
            }
        }
        return PuertoAbierto(d, banner?.takeIf { it.isNotEmpty() }, https)
    }

    private fun leer(s: Socket, max: Int): String {
        val buf = ByteArray(max)
        var n = 0
        try {
            val ent = s.getInputStream()
            while (n < max) {
                val r = ent.read(buf, n, max - n)
                if (r < 0) break
                n += r
            }
        } catch (e: Exception) {
            // Tiempo de lectura agotado: se queda con lo recibido.
        }
        return String(buf, 0, n, Charsets.ISO_8859_1)
    }

    fun limpiar(texto: String): String {
        val sb = StringBuilder()
        for (c in texto) {
            if (c.code in 32..126) sb.append(c) else if (c == '\n' || c == '\r') sb.append(' ')
            if (sb.length >= 80) break
        }
        return sb.toString().trim()
    }
}

class ResultadoHttp(val estado: Int, val servidor: String?, val redirigeAHttps: Boolean, val resumen: String)

/** Lee la respuesta a un HEAD: código, cabecera Server y si redirige a HTTPS. */
object ParserHttp {
    fun analizar(texto: String): ResultadoHttp {
        val lineas = texto.split("\r\n", "\n")
        val primera = lineas.firstOrNull() ?: ""
        val m = Regex("^HTTP/\\d\\.\\d\\s+(\\d{3})").find(primera)
        val estado = m?.groupValues?.get(1)?.toIntOrNull() ?: 0
        var servidor: String? = null
        var ubicacion: String? = null
        for (l in lineas.drop(1)) {
            val i = l.indexOf(':')
            if (i <= 0) continue
            val k = l.substring(0, i).trim().lowercase()
            val v = l.substring(i + 1).trim()
            if (k == "server") servidor = v
            if (k == "location") ubicacion = v
        }
        val https = estado in 300..399 && ubicacion != null && ubicacion.lowercase().startsWith("https://")
        val partes = ArrayList<String>()
        if (estado != 0) partes.add("HTTP " + estado)
        if (servidor != null) partes.add(servidor)
        if (https) partes.add("redirige a HTTPS")
        return ResultadoHttp(estado, servidor, https, EscanerPuertos.limpiar(partes.joinToString(" · ")))
    }
}
