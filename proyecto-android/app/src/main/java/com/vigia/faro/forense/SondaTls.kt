package com.vigia.faro.forense

import com.vigia.faro.Riesgo
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

/**
 * Detecta la interceptación de HTTPS: se conecta a webs conocidas con la validación normal de Android y mira si el
 * certificado es válido y si la cadena pasa por una autoridad instalada por el usuario. No envía ni recibe datos.
 */
object SondaTls {

    class Resultado(
        val host: String,
        val conectado: Boolean,
        val valido: Boolean,
        val error: String?,
        val emisor: String?,
        val huella: String?,
        val porCaUsuario: Boolean
    )

    private val HOSTS = listOf("www.google.com", "www.cloudflare.com", "github.com", "www.wikipedia.org")

    private fun nombreCorto(dn: String): String {
        val o = Regex("(?:^|,)O=([^,]+)").find(dn)?.groupValues?.get(1)
        val cn = Regex("(?:^|,)CN=([^,]+)").find(dn)?.groupValues?.get(1)
        return (o ?: cn ?: dn).take(50)
    }

    fun sondear(host: String, ca: TelefonoForense.CaUsuario): Resultado {
        val plano = Socket()
        try {
            plano.connect(InetSocketAddress(host, 443), 4000)
        } catch (e: Exception) {
            try {
                plano.close()
            } catch (e2: Exception) {
            }
            return Resultado(host, false, false, "sin conexión", null, null, false)
        }
        try {
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, null, null)
            val ssl = ctx.socketFactory.createSocket(plano, host, 443, true) as SSLSocket
            ssl.soTimeout = 4000
            ssl.startHandshake()
            val cadena = ssl.session.peerCertificates.filterIsInstance<X509Certificate>()
            val nombreOk = HttpsURLConnection.getDefaultHostnameVerifier().verify(host, ssl.session)
            val hoja = cadena.firstOrNull()
            val huella = if (hoja != null) Huellas.sha256(hoja.encoded) else null
            val porCa = cadena.any {
                ca.huellas.contains(Huellas.sha256(it.encoded)) ||
                    ca.sujetos.contains(it.issuerX500Principal.name) ||
                    ca.sujetos.contains(it.subjectX500Principal.name)
            }
            val emisor = if (hoja != null) nombreCorto(hoja.issuerX500Principal.name) else null
            ssl.close()
            return Resultado(host, true, nombreOk, if (nombreOk) null else "el nombre del certificado no coincide", emisor, huella, porCa)
        } catch (e: Exception) {
            return Resultado(host, true, false, (e.message ?: e.javaClass.simpleName).take(90), null, null, false)
        } finally {
            try {
                plano.close()
            } catch (e: Exception) {
            }
        }
    }

    fun analizar(datos: DatosForenses, enPortal: Boolean) {
        val ca = TelefonoForense.infoCaUsuario()
        val resultados = HOSTS.map { sondear(it, ca) }
        val lineas = ArrayList<String>()
        for (r in resultados) {
            lineas.add(
                r.host + ": " + (if (!r.conectado) "sin conexión" else if (r.valido) "válido" else "NO VÁLIDO (" + r.error + ")") +
                    (if (r.emisor != null) " · emisor " + r.emisor else "") + (if (r.huella != null) " · " + r.huella.take(16) else "")
            )
        }
        datos.seccion("HTTPS (certificados de webs conocidas)", lineas)

        val conectados = resultados.filter { it.conectado }
        if (conectados.isEmpty()) {
            datos.limitaciones.add("No se pudo abrir ninguna conexión HTTPS: no se comprobó la interceptación TLS.")
            return
        }
        val porCa = conectados.filter { it.porCaUsuario }
        if (porCa.isNotEmpty()) {
            datos.hallazgo(
                Riesgo.CRITICO, "El tráfico HTTPS pasa por una autoridad instalada por el usuario",
                "Los certificados de " + porCa.joinToString(", ") { it.host } + " están firmados por una CA que se instaló a mano en este teléfono. Quien la controle puede ver y alterar tu tráfico cifrado.",
                "Quita esa CA (Ajustes > Seguridad > Credenciales de confianza > Usuario) y evita esta red hasta aclararlo.", "TLS"
            )
        }
        val malos = conectados.filter { !it.valido }
        if (malos.size >= 2 || (malos.size == 1 && conectados.size == 1)) {
            datos.hallazgo(
                if (enPortal) Riesgo.BAJO else Riesgo.ALTO,
                "Varias webs presentan certificados no válidos",
                (if (enPortal) "Es esperable en una red con portal cautivo, que intercepta las conexiones hasta que inicies sesión. " else "Puede ser una interceptación de HTTPS (alguien se hace pasar por esas webs) o un reloj del teléfono mal puesto. ") +
                    "Afectadas: " + malos.joinToString(", ") { it.host } + ".",
                if (enPortal) "Inicia sesión en el portal y repite el análisis." else "No introduzcas contraseñas en esta red. Comprueba la fecha del teléfono y prueba con datos móviles.", "TLS"
            )
        } else if (malos.size == 1) {
            datos.hallazgo(
                Riesgo.MEDIO, "Un certificado HTTPS no válido (" + malos[0].host + ")",
                "Motivo: " + (malos[0].error ?: "desconocido") + ". Un caso aislado puede ser un fallo puntual; si se repite, podría ser interceptación.",
                "Repite el análisis. Si vuelve a salir, evita esta red.", "TLS"
            )
        }
    }
}
