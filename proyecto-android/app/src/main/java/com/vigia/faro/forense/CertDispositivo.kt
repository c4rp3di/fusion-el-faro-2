package com.vigia.faro.forense

import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Lee el certificado que presenta un equipo de la red en su puerto HTTPS (paneles de routers, cámaras, NAS).
 * Solo se hace el saludo TLS para LEER el certificado: no se valida (casi todos son autofirmados) ni se envía nada.
 */
object CertDispositivo {

    class Info(
        val sujeto: String,
        val emisor: String,
        val autofirmado: Boolean,
        val caduca: Long,
        val caducado: Boolean,
        val algoritmo: String,
        val bitsClave: Int?,
        val debil: Boolean
    ) {
        fun resumen(): String {
            val sb = StringBuilder(sujeto.take(60))
            if (autofirmado) sb.append(" · autofirmado")
            if (caducado) sb.append(" · CADUCADO")
            sb.append(" · ").append(algoritmo)
            if (bitsClave != null) sb.append(" ").append(bitsClave).append(" bits")
            return sb.toString()
        }
    }

    private val SIN_VALIDAR = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    fun leer(ip: String, puerto: Int): Info? {
        val plano = Socket()
        return try {
            plano.connect(InetSocketAddress(ip, puerto), 900)
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf<TrustManager>(SIN_VALIDAR), SecureRandom())
            val ssl = ctx.socketFactory.createSocket(plano, ip, puerto, true) as SSLSocket
            ssl.soTimeout = 1500
            ssl.startHandshake()
            val cert = ssl.session.peerCertificates.firstOrNull() as? X509Certificate
            ssl.close()
            if (cert == null) return null
            val bits = (cert.publicKey as? RSAPublicKey)?.modulus?.bitLength()
            val alg = cert.sigAlgName
            val mayus = alg.uppercase()
            val caduca = cert.notAfter.time
            Info(
                sujeto = cert.subjectX500Principal.name,
                emisor = cert.issuerX500Principal.name,
                autofirmado = cert.subjectX500Principal == cert.issuerX500Principal,
                caduca = caduca,
                caducado = caduca < System.currentTimeMillis(),
                algoritmo = alg,
                bitsClave = bits,
                debil = mayus.startsWith("MD5") || mayus.startsWith("SHA1") || (bits != null && bits < 2048)
            )
        } catch (e: Exception) {
            null
        } finally {
            try {
                plano.close()
            } catch (e: Exception) {
            }
        }
    }
}
