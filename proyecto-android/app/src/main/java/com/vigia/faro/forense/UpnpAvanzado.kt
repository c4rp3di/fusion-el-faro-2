package com.vigia.faro.forense

import com.vigia.core.red.UtilRed
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Lee del router (solo lectura) la IP externa y la lista de reenvíos de puertos que UPnP ha abierto hacia internet.
 * Es una señal forense importante: el malware y algunos programas abren puertos en el router sin avisar.
 * Solo se consulta al propio router, en su red privada, y únicamente con acciones «Get».
 */
object UpnpAvanzado {

    class Mapeo(
        val protocolo: String,
        val puertoExterno: Int,
        val clienteInterno: String,
        val puertoInterno: Int,
        val activo: Boolean,
        val descripcion: String,
        val remoto: String
    )

    class Resultado(val servicio: String, val ipExterna: String?, val mapeos: List<Mapeo>, val completo: Boolean)

    private const val MAX_MAPEOS = 48

    private fun leer(ent: InputStream): String {
        val salida = java.io.ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (salida.size() < 65536) {
            val n = ent.read(buf)
            if (n < 0) break
            salida.write(buf, 0, n)
        }
        return String(salida.toByteArray(), Charsets.UTF_8)
    }

    private fun etiqueta(xml: String, nombre: String): String? =
        Regex("<" + nombre + ">([^<]*)</" + nombre + ">").find(xml)?.groupValues?.get(1)?.trim()

    private fun permitida(u: URL, ipRouter: String): Boolean {
        if (u.protocol != "http" || u.host != ipRouter) return false
        val n = UtilRed.parseIpv4(ipRouter) ?: return false
        return UtilRed.esIpPrivada(n)
    }

    private fun soap(url: URL, tipoServicio: String, accion: String, argumentos: String): Pair<Int, String>? {
        return try {
            val cuerpo = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:" + accion + " xmlns:u=\"" + tipoServicio + "\">" +
                argumentos + "</u:" + accion + "></s:Body></s:Envelope>"
            val con = url.openConnection() as HttpURLConnection
            con.requestMethod = "POST"
            con.doOutput = true
            con.connectTimeout = 2000
            con.readTimeout = 2500
            con.instanceFollowRedirects = false
            con.setRequestProperty("Content-Type", "text/xml; charset=\"utf-8\"")
            con.setRequestProperty("SOAPAction", "\"" + tipoServicio + "#" + accion + "\"")
            con.outputStream.use { it.write(cuerpo.toByteArray(Charsets.UTF_8)) }
            val codigo = con.responseCode
            val flujo = if (codigo in 200..299) con.inputStream else con.errorStream
            val texto = if (flujo != null) flujo.use { leer(it) } else ""
            con.disconnect()
            Pair(codigo, texto)
        } catch (e: Exception) {
            null
        }
    }

    fun consultar(ubicacion: String, ipRouter: String): Resultado? {
        return try {
            val desc = URL(ubicacion)
            if (!permitida(desc, ipRouter)) return null
            val con = desc.openConnection() as HttpURLConnection
            con.connectTimeout = 1500
            con.readTimeout = 1500
            con.instanceFollowRedirects = false
            val xml = con.inputStream.use { leer(it) }
            con.disconnect()

            var tipo: String? = null
            var control: String? = null
            for (m in Regex("<service>(.*?)</service>", RegexOption.DOT_MATCHES_ALL).findAll(xml)) {
                val bloque = m.groupValues[1]
                val t = etiqueta(bloque, "serviceType") ?: continue
                if (t.contains("WANIPConnection") || t.contains("WANPPPConnection")) {
                    tipo = t
                    control = etiqueta(bloque, "controlURL")
                    break
                }
            }
            if (tipo == null || control == null) return null
            val urlControl = URL(desc, control)
            if (!permitida(urlControl, ipRouter)) return null

            var ipExterna: String? = null
            val r = soap(urlControl, tipo, "GetExternalIPAddress", "")
            if (r != null && r.first == 200) ipExterna = etiqueta(r.second, "NewExternalIPAddress")

            val mapeos = ArrayList<Mapeo>()
            var completo = true
            for (i in 0 until MAX_MAPEOS) {
                val e = soap(urlControl, tipo, "GetGenericPortMappingEntry", "<NewPortMappingIndex>" + i + "</NewPortMappingIndex>")
                if (e == null || e.first != 200) break
                val x = e.second
                mapeos.add(
                    Mapeo(
                        protocolo = etiqueta(x, "NewProtocol") ?: "?",
                        puertoExterno = etiqueta(x, "NewExternalPort")?.toIntOrNull() ?: 0,
                        clienteInterno = etiqueta(x, "NewInternalClient") ?: "?",
                        puertoInterno = etiqueta(x, "NewInternalPort")?.toIntOrNull() ?: 0,
                        activo = (etiqueta(x, "NewEnabled") ?: "1") != "0",
                        descripcion = etiqueta(x, "NewPortMappingDescription") ?: "",
                        remoto = etiqueta(x, "NewRemoteHost") ?: ""
                    )
                )
                if (i == MAX_MAPEOS - 1) completo = false
            }
            Resultado(tipo, ipExterna, mapeos, completo)
        } catch (e: Exception) {
            null
        }
    }
}
