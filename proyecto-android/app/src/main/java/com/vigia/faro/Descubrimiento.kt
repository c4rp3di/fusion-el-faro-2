package com.vigia.faro

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import com.vigia.core.red.UtilRed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.URL
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume

enum class Tipo(val etiqueta: String, val icono: String) {
    ROUTER("Router", "📡"),
    ESTE("Este teléfono", "📱"),
    MOVIL("Teléfono o tablet", "📱"),
    PC("Ordenador", "💻"),
    TV("TV / reproductor", "📺"),
    IMPRESORA("Impresora", "🖨"),
    CAMARA("Cámara IP", "📷"),
    NAS("Almacenamiento (NAS)", "🗄"),
    ALTAVOZ("Altavoz / domótica", "🔊"),
    DESCONOCIDO("Dispositivo sin identificar", "❔")
}

/** Un equipo de la red con todo lo que se averiguó de él. */
class Dispositivo(val ip: String) {
    var nombre: String? = null
    var mac: String? = null
    var fabricante: String? = null
    var modelo: String? = null
    var esRouter = false
    var esEsteTelefono = false
    var nuevo = false
    var tipo = Tipo.DESCONOCIDO
    val servicios = LinkedHashSet<String>()
    val puertos = ArrayList<PuertoAbierto>()

    /** Certificado TLS que presenta el equipo en su puerto HTTPS, si lo tiene. */
    var certInfo: com.vigia.faro.forense.CertDispositivo.Info? = null

    val certificado: String? get() = certInfo?.resumen()

    val macAleatoria: Boolean get() = com.vigia.faro.forense.Oui.esAleatoria(mac)

    val riesgoMaximo: Riesgo
        get() = puertos.map { it.def.riesgo }.minByOrNull { it.ordinal } ?: Riesgo.INFO

    /** Identificador lo más estable posible para reconocerlo en otra visita. */
    val identificador: String get() = mac ?: nombre ?: ip

    val nombreVisible: String
        get() = nombre ?: modelo ?: fabricante ?: tipo.etiqueta
}

class RespuestaSsdp(val ip: String, val st: String, val usn: String, val servidor: String, val ubicacion: String)

class DescripcionUpnp(val nombre: String?, val fabricante: String?, val modelo: String?)

class ServicioMdnsFaro(val nombre: String, val tipo: String, val ip: String)

object Descubridor {

    // ------------------------------------------------------------------ rango y barrido

    /** Direcciones a revisar: la subred del teléfono, limitada a un /24 como máximo (254 equipos). */
    fun rango(ipLocal: String, prefijo: Int): List<String> {
        val ip = UtilRed.parseIpv4(ipLocal) ?: return emptyList()
        val p = if (prefijo < 24) 24 else prefijo
        if (p >= 31) return emptyList()
        val mascara = -1 shl (32 - p)
        val red = ip and mascara
        val difusion = red or mascara.inv()
        val lista = ArrayList<String>()
        var a = red + 1
        while (a < difusion) {
            if (a != ip) lista.add(UtilRed.ipv4ATexto(a))
            a++
        }
        return lista
    }

    private fun existePing(): Boolean = File("/system/bin/ping").exists()

    /** ICMP con el comando `ping` del sistema (Android no deja abrir sockets ICMP en bruto). */
    private fun pingIcmp(ip: String): Boolean {
        return try {
            val p = ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "1", ip).redirectErrorStream(true).start()
            val terminado = p.waitFor(3, TimeUnit.SECONDS)
            if (!terminado) {
                p.destroy()
                false
            } else {
                val ok = p.exitValue() == 0
                p.destroy()
                ok
            }
        } catch (e: Exception) {
            false
        }
    }

    private val PUERTOS_VIDA = listOf(80, 443, 445, 22, 8080, 62078, 8009)

    /** Un equipo está vivo si acepta O RECHAZA una conexión: un rechazo también demuestra que contestó. */
    private suspend fun vivoPorTcp(ip: String): Boolean = coroutineScope {
        PUERTOS_VIDA.map { p -> async(Dispatchers.IO) { EscanerPuertos.sondear(ip, p, 400) != SondeoTcp.SIN_RESPUESTA } }
            .awaitAll()
            .any { it }
    }

    /** Devuelve las IP que responden. [progreso] recibe (revisadas, total). */
    suspend fun barrido(ips: List<String>, concurrencia: Int = 40, progreso: (Int, Int) -> Unit): Set<String> = coroutineScope {
        val sem = Semaphore(concurrencia)
        val usarPing = existePing()
        val vivos = java.util.Collections.synchronizedSet(HashSet<String>())
        var hechos = 0
        val total = ips.size
        ips.map { ip ->
            async(Dispatchers.IO) {
                sem.withPermit {
                    val vivo = (usarPing && pingIcmp(ip)) || vivoPorTcp(ip)
                    if (vivo) vivos.add(ip)
                    synchronized(vivos) {
                        hechos++
                        progreso(hechos, total)
                    }
                }
            }
        }.awaitAll()
        HashSet(vivos)
    }

    /** Tabla ARP del sistema. Android 10+ la oculta a las apps: si no se puede leer, devuelve un mapa vacío. */
    fun vecinos(): Map<String, String> {
        val res = HashMap<String, String>()
        try {
            for (l in File("/proc/net/arp").readLines().drop(1)) {
                val p = l.trim().split(Regex("\\s+"))
                if (p.size >= 4 && p[3] != "00:00:00:00:00:00" && p[3].contains(':')) res[p[0]] = p[3].lowercase()
            }
        } catch (e: Exception) {
        }
        return res
    }

    // ------------------------------------------------------------------ nombres

    fun nombreInverso(ip: String): String? {
        return try {
            val n = InetAddress.getByName(ip).canonicalHostName
            if (n == ip || n.isEmpty()) null else n
        } catch (e: Exception) {
            null
        }
    }

    /** Consulta NBSTAT (UDP 137): los equipos Windows y muchos NAS responden con su nombre. */
    fun consultaNetbios(): ByteArray {
        val b = ByteArray(50)
        b[0] = 0x12
        b[1] = 0x34
        b[5] = 1
        b[12] = 0x20
        b[13] = 'C'.code.toByte()
        b[14] = 'K'.code.toByte()
        for (i in 15 until 45) b[i] = 'A'.code.toByte()
        b[45] = 0
        b[47] = 0x21
        b[49] = 1
        return b
    }

    /** Extrae el primer nombre único (sufijo 0x00) de una respuesta NBSTAT. */
    fun nombreDeRespuestaNetbios(d: ByteArray, largo: Int): String? {
        if (largo < 57) return null
        // El nombre de la respuesta suele ir completo (34 bytes) pero puede venir comprimido (2 bytes).
        val largoNombre = if ((d[12].toInt() and 0xC0) == 0xC0) 2 else 34
        val inicio = 12 + largoNombre + 10
        if (inicio >= largo) return null
        val n = d[inicio].toInt() and 0xFF
        var pos = inicio + 1
        for (i in 0 until n) {
            if (pos + 18 > largo) break
            val sufijo = d[pos + 15].toInt() and 0xFF
            val flags = ((d[pos + 16].toInt() and 0xFF) shl 8) or (d[pos + 17].toInt() and 0xFF)
            val grupo = (flags and 0x8000) != 0
            if (sufijo == 0 && !grupo) {
                val nombre = String(d, pos, 15, Charsets.ISO_8859_1).trim()
                if (nombre.isNotEmpty()) return EscanerPuertos.limpiar(nombre)
            }
            pos += 18
        }
        return null
    }

    fun nombreNetbios(ip: String): String? {
        var s: DatagramSocket? = null
        return try {
            val sock = DatagramSocket()
            s = sock
            sock.soTimeout = 700
            val q = consultaNetbios()
            sock.send(DatagramPacket(q, q.size, InetAddress.getByName(ip), 137))
            val buf = ByteArray(1024)
            val r = DatagramPacket(buf, buf.size)
            sock.receive(r)
            nombreDeRespuestaNetbios(buf, r.length)
        } catch (e: Exception) {
            null
        } finally {
            s?.close()
        }
    }

    // ------------------------------------------------------------------ UPnP / SSDP

    fun analizarSsdp(texto: String, ip: String): RespuestaSsdp {
        var st = ""
        var usn = ""
        var servidor = ""
        var ubicacion = ""
        for (l in texto.split("\r\n", "\n")) {
            val i = l.indexOf(':')
            if (i <= 0) continue
            val k = l.substring(0, i).trim().uppercase()
            val v = l.substring(i + 1).trim()
            when (k) {
                "ST", "NT" -> st = v
                "USN" -> usn = v
                "SERVER" -> servidor = v
                "LOCATION" -> ubicacion = v
            }
        }
        return RespuestaSsdp(ip, st, usn, servidor, ubicacion)
    }

    /** Busca equipos UPnP durante [duracionMs]. */
    suspend fun ssdp(c: Context, duracionMs: Long): List<RespuestaSsdp> = withContext(Dispatchers.IO) {
        val res = ArrayList<RespuestaSsdp>()
        val wm = c.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val cerrojo = try {
            val l = wm.createMulticastLock("faro")
            l.setReferenceCounted(false)
            l.acquire()
            l
        } catch (e: Exception) {
            null
        }
        try {
            val sock = DatagramSocket(null)
            try {
                sock.reuseAddress = true
                sock.bind(InetSocketAddress(0))
                sock.soTimeout = 400
                val msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
                    .toByteArray(Charsets.US_ASCII)
                val destino = InetAddress.getByName("239.255.255.250")
                sock.send(DatagramPacket(msg, msg.size, destino, 1900))
                sock.send(DatagramPacket(msg, msg.size, destino, 1900))
                val fin = System.currentTimeMillis() + duracionMs
                val buf = ByteArray(2048)
                while (System.currentTimeMillis() < fin) {
                    try {
                        val p = DatagramPacket(buf, buf.size)
                        sock.receive(p)
                        val ip = p.address.hostAddress ?: continue
                        res.add(analizarSsdp(String(p.data, 0, p.length, Charsets.ISO_8859_1), ip))
                    } catch (e: SocketTimeoutException) {
                    }
                }
            } finally {
                sock.close()
            }
        } catch (e: Exception) {
        } finally {
            try {
                cerrojo?.release()
            } catch (e: Exception) {
            }
        }
        res
    }

    /**
     * Descarga la descripción UPnP de un equipo. Solo se acepta una URL http cuyo servidor sea el MISMO equipo que
     * respondió y esté en una red privada: un dispositivo no puede hacer que la app consulte otra dirección.
     */
    fun descripcionUpnp(url: String, ipEsperada: String): DescripcionUpnp? {
        return try {
            val u = URL(url)
            if (u.protocol != "http" || u.host != ipEsperada) return null
            val ipNum = UtilRed.parseIpv4(ipEsperada) ?: return null
            if (!UtilRed.esIpPrivada(ipNum)) return null
            val con = u.openConnection() as java.net.HttpURLConnection
            con.connectTimeout = 1500
            con.readTimeout = 1500
            con.instanceFollowRedirects = false
            val bytes = con.inputStream.use { ent ->
                val salida = java.io.ByteArrayOutputStream()
                val buf = ByteArray(4096)
                while (salida.size() < 65536) {
                    val n = ent.read(buf)
                    if (n < 0) break
                    salida.write(buf, 0, n)
                }
                salida.toByteArray()
            }
            con.disconnect()
            val xml = String(bytes, Charsets.UTF_8)
            fun etiqueta(n: String): String? = Regex("<" + n + ">([^<]{1,80})</" + n + ">").find(xml)?.groupValues?.get(1)?.trim()
            DescripcionUpnp(etiqueta("friendlyName"), etiqueta("manufacturer"), etiqueta("modelName"))
        } catch (e: Exception) {
            null
        }
    }

    // ------------------------------------------------------------------ mDNS

    private val TIPOS_MDNS = listOf(
        "_googlecast._tcp", "_airplay._tcp", "_ipp._tcp", "_printer._tcp", "_hap._tcp",
        "_smb._tcp", "_http._tcp", "_workstation._tcp", "_companion-link._tcp", "_spotify-connect._tcp"
    )

    @Suppress("DEPRECATION")
    suspend fun mdns(c: Context, duracionMs: Long): List<ServicioMdnsFaro> = withContext(Dispatchers.IO) {
        val nsd = c.applicationContext.getSystemService(NsdManager::class.java)
        val cola = ConcurrentLinkedQueue<NsdServiceInfo>()
        val escuchas = ArrayList<NsdManager.DiscoveryListener>()
        for (tipo in TIPOS_MDNS) {
            val l = object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(t: String) {}
                override fun onStartDiscoveryFailed(t: String, codigo: Int) {}
                override fun onStopDiscoveryFailed(t: String, codigo: Int) {}
                override fun onDiscoveryStopped(t: String) {}
                override fun onServiceLost(info: NsdServiceInfo) {}
                override fun onServiceFound(info: NsdServiceInfo) {
                    cola.add(info)
                }
            }
            try {
                nsd.discoverServices(tipo, NsdManager.PROTOCOL_DNS_SD, l)
                escuchas.add(l)
            } catch (e: Exception) {
            }
        }
        val res = ArrayList<ServicioMdnsFaro>()
        val fin = System.currentTimeMillis() + duracionMs
        while (System.currentTimeMillis() < fin) {
            val info = cola.poll()
            if (info == null) {
                delay(150L)
                continue
            }
            val r = resolver(nsd, info)
            if (r != null) res.add(r)
        }
        for (l in escuchas) {
            try {
                nsd.stopServiceDiscovery(l)
            } catch (e: Exception) {
            }
        }
        res
    }

    @Suppress("DEPRECATION")
    private suspend fun resolver(nsd: NsdManager, info: NsdServiceInfo): ServicioMdnsFaro? {
        return withTimeoutOrNull(1500L) {
            suspendCancellableCoroutine<ServicioMdnsFaro?> { cont ->
                nsd.resolveService(info, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(i: NsdServiceInfo, codigo: Int) {
                        if (cont.isActive) cont.resume(null)
                    }

                    override fun onServiceResolved(i: NsdServiceInfo) {
                        val h = i.host
                        if (cont.isActive) {
                            if (h is Inet4Address && h.hostAddress != null) {
                                cont.resume(ServicioMdnsFaro(i.serviceName ?: "", i.serviceType ?: "", h.hostAddress ?: ""))
                            } else {
                                cont.resume(null)
                            }
                        }
                    }
                })
            }
        }
    }

    // ------------------------------------------------------------------ clasificación

    /** Deduce qué es un equipo a partir de sus puertos, nombres y servicios anunciados. */
    fun clasificar(d: Dispositivo) {
        if (d.esEsteTelefono) {
            d.tipo = Tipo.ESTE
            return
        }
        if (d.esRouter) {
            d.tipo = Tipo.ROUTER
            return
        }
        val abiertos = d.puertos.map { it.def.puerto }.toSet()
        val texto = (listOf(d.nombre, d.fabricante, d.modelo) + d.servicios).filterNotNull().joinToString(" ").lowercase()
        fun contiene(vararg claves: String): Boolean = claves.any { texto.contains(it) }
        d.tipo = when {
            abiertos.contains(9100) || abiertos.contains(631) || abiertos.contains(515) ||
                contiene("_ipp", "_printer", "printer", "impresora", "laserjet", "deskjet", "officejet", "epson", "brother") -> Tipo.IMPRESORA
            abiertos.contains(554) || contiene("camera", "ipcam", "hikvision", "dahua", "reolink", "imou", "tapo", "wyze") -> Tipo.CAMARA
            abiertos.contains(8008) || abiertos.contains(8009) ||
                contiene("_googlecast", "chromecast", "bravia", "tizen", "webos", "roku", "firetv", "smarttv", "mediarenderer", "android tv", "_airplay") -> Tipo.TV
            contiene("sonos", "alexa", "echo", "homepod", "_hap", "homekit", "hue", "nest", "_spotify-connect", "espressif", "tuya", "shelly") -> Tipo.ALTAVOZ
            abiertos.contains(5000) || contiene("synology", "diskstation", "qnap", "nas", "readynas") -> Tipo.NAS
            abiertos.contains(62078) || contiene("iphone", "ipad", "android", "galaxy", "pixel", "xiaomi", "redmi", "huawei", "oneplus", "oppo", "_companion-link") -> Tipo.MOVIL
            abiertos.contains(445) || abiertos.contains(139) || abiertos.contains(3389) || abiertos.contains(5900) ||
                contiene("desktop", "laptop", "windows", "macbook", "imac", "_workstation", "_smb", "raspberry", "vmware", "virtualbox", "qemu") -> Tipo.PC
            else -> Tipo.DESCONOCIDO
        }
    }
}
