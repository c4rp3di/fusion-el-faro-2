package com.vigia.faro.forense

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/**
 * Firma propia de los informes: ECDSA P-256 con una clave que se crea y se queda en el Android Keystore
 * (en hardware si el teléfono lo permite). El informe incluye la clave pública para poder verificarlo.
 * El plan original pedía Ed25519; no está disponible en todas las versiones de Android que se soportan.
 */
object Firma {
    private const val ALIAS = "faro_firma"
    const val FORMATO = "faro-evidencia-1"

    private fun asegurarClave() {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        if (ks.containsAlias(ALIAS)) return
        val generador = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generador.initialize(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
        )
        generador.generateKeyPair()
    }

    /** Clave pública de este teléfono, si ya se creó. */
    fun clavePublicaPropia(): ByteArray? {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            if (!ks.containsAlias(ALIAS)) null else ks.getCertificate(ALIAS)?.publicKey?.encoded
        } catch (e: Exception) {
            null
        }
    }

    class Verificacion(val valida: Boolean, val esDeEsteTelefono: Boolean, val huellaClave: String)

    /** Comprueba la firma de un sobre de informe con la clave pública que lleva dentro. */
    fun verificar(sobre: JSONObject): Verificacion {
        return try {
            val f = sobre.getJSONObject("firma")
            val publica = Base64.decode(f.getString("clave_publica"), Base64.NO_WRAP)
            val valor = Base64.decode(f.getString("valor"), Base64.NO_WRAP)
            val clave = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publica))
            val v = Signature.getInstance("SHA256withECDSA")
            v.initVerify(clave)
            v.update(sobre.getString("contenido").toByteArray(Charsets.UTF_8))
            val ok = v.verify(valor)
            val propia = clavePublicaPropia()
            val huella = java.security.MessageDigest.getInstance("SHA-256").digest(publica)
            val sb = StringBuilder()
            for (i in 0 until 8) sb.append(String.format("%02x", huella[i].toInt() and 0xFF))
            Verificacion(ok, propia != null && propia.contentEquals(publica), sb.toString())
        } catch (e: Exception) {
            Verificacion(false, false, "")
        }
    }

    /** Envuelve el texto del informe (JSON) con su firma. El texto firmado es exactamente el campo «contenido». */
    fun sobre(contenido: String): JSONObject {
        asegurarClave()
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val entrada = ks.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
        val firma = Signature.getInstance("SHA256withECDSA")
        firma.initSign(entrada.privateKey)
        firma.update(contenido.toByteArray(Charsets.UTF_8))
        val valor = firma.sign()
        val publica = entrada.certificate.publicKey.encoded
        return JSONObject()
            .put("formato", FORMATO)
            .put("contenido", contenido)
            .put(
                "firma",
                JSONObject()
                    .put("algoritmo", "SHA256withECDSA")
                    .put("clave_publica", Base64.encodeToString(publica, Base64.NO_WRAP))
                    .put("valor", Base64.encodeToString(valor, Base64.NO_WRAP))
            )
    }
}
