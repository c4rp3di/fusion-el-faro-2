package com.vigia.faro.forense

import android.content.Context
import android.net.wifi.WifiManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.UUID

/**
 * WS-Discovery (UDP 3702, multidifusión): cámaras ONVIF, impresoras y equipos Windows contestan diciendo qué son y en qué
 * dirección se administran. Es descubrimiento puro: se envía una sonda estándar y se leen las respuestas.
 */
object WsDiscovery {

    class Respuesta(val ip: String, val tipos: String, val direcciones: String, val ambitos: String)

    private fun sonda(): ByteArray {
        val xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
            "xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">" +
            "<soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>" +
            "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>" +
            "<wsa:MessageID>urn:uuid:" + UUID.randomUUID().toString() + "</wsa:MessageID></soap:Header>" +
            "<soap:Body><wsd:Probe/></soap:Body></soap:Envelope>"
        return xml.toByteArray(Charsets.UTF_8)
    }

    private fun etiqueta(xml: String, nombre: String): String {
        val m = Regex("<(?:\\w+:)?" + nombre + "[^>]*>([^<]*)</(?:\\w+:)?" + nombre + ">").find(xml)
        return m?.groupValues?.get(1)?.trim() ?: ""
    }

    /** Lee una respuesta WS-Discovery. Devuelve null si no tiene ni tipos ni direcciones. */
    fun leer(ip: String, xml: String): Respuesta? {
        val tipos = etiqueta(xml, "Types")
        val dir = etiqueta(xml, "XAddrs")
        val ambitos = etiqueta(xml, "Scopes")
        if (tipos.isEmpty() && dir.isEmpty()) return null
        return Respuesta(ip, tipos, dir, ambitos)
    }

    suspend fun descubrir(c: Context, duracionMs: Long): List<Respuesta> = withContext(Dispatchers.IO) {
        val res = LinkedHashMap<String, Respuesta>()
        var lock: WifiManager.MulticastLock? = null
        var socket: DatagramSocket? = null
        try {
            val wm = c.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            lock = wm.createMulticastLock("faro-wsd")
            lock.setReferenceCounted(false)
            lock.acquire()
            socket = DatagramSocket()
            val datos = sonda()
            val destino = InetAddress.getByName("239.255.255.250")
            socket.send(DatagramPacket(datos, datos.size, destino, 3702))
            val fin = System.currentTimeMillis() + duracionMs
            val buf = ByteArray(16384)
            while (System.currentTimeMillis() < fin) {
                val restante = (fin - System.currentTimeMillis()).toInt()
                if (restante <= 0) break
                socket.soTimeout = restante
                val p = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(p)
                } catch (e: Exception) {
                    break
                }
                val ip = p.address.hostAddress ?: continue
                val xml = String(p.data, 0, p.length, Charsets.UTF_8)
                val r = leer(ip, xml) ?: continue
                if (!res.containsKey(ip)) res[ip] = r
            }
        } catch (e: Exception) {
            // Sin multidifusión (red que la bloquea): no hay respuestas.
        } finally {
            try {
                socket?.close()
            } catch (e: Exception) {
            }
            try {
                if (lock != null && lock.isHeld) lock.release()
            } catch (e: Exception) {
            }
        }
        res.values.toList()
    }

    /** Texto que se añade a los «servicios» del equipo para que lo use la clasificación (cámara, impresora, ordenador). */
    fun resumen(r: Respuesta): String {
        val nombre = Regex("name/([^/\\s]+)").find(r.ambitos)?.groupValues?.get(1)
        val hardware = Regex("hardware/([^/\\s]+)").find(r.ambitos)?.groupValues?.get(1)
        val sb = StringBuilder("WS-Discovery: ").append(r.tipos)
        if (nombre != null) sb.append(" · ").append(nombre)
        if (hardware != null) sb.append(" · ").append(hardware)
        return sb.toString()
    }
}
