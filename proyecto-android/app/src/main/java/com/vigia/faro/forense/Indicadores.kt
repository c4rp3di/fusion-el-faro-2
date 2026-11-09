package com.vigia.faro.forense

import android.content.Context
import com.vigia.core.red.UtilRed
import com.vigia.core.seguridad.AlmacenClaves
import com.vigia.core.seguridad.PerdidaClave
import org.json.JSONArray
import org.json.JSONObject

/**
 * Lista de indicadores de compromiso (IOC) que aporta el usuario: IP, dominios y nombres de paquete de software espía
 * o malicioso, por ejemplo los de un informe de Amnesty/MVT (STIX2) o una lista de texto. El Faro NO trae ninguna
 * lista propia: solo compara lo que encuentra con lo que le des. Se guarda cifrada con el Keystore.
 */
object Indicadores {
    private const val CLAVE = "ioc_v1"
    private const val MAX = 20000

    private fun almacen(c: Context) = AlmacenClaves.paraApp(c, "faro", PerdidaClave.REGENERAR_Y_BORRAR_BD)

    class Lista(val origen: String, val importada: Long, val valores: Set<String>)

    fun cargar(c: Context): Lista? {
        val texto = almacen(c).leerSecreto(CLAVE) ?: return null
        return try {
            val j = JSONObject(texto)
            val arr = j.getJSONArray("valores")
            val v = HashSet<String>()
            for (i in 0 until arr.length()) v.add(arr.getString(i))
            Lista(j.optString("origen"), j.optLong("importada"), v)
        } catch (e: Exception) {
            null
        }
    }

    fun borrar(c: Context) {
        almacen(c).guardarSecreto(CLAVE, "")
    }

    /** Devuelve cuántos indicadores válidos se importaron (0 si el texto no tenía ninguno). */
    fun importar(c: Context, texto: String, origen: String): Int {
        val v = extraer(texto)
        if (v.isEmpty()) return 0
        val arr = JSONArray()
        for (x in v) arr.put(x)
        val j = JSONObject().put("origen", origen).put("importada", System.currentTimeMillis()).put("valores", arr)
        almacen(c).guardarSecreto(CLAVE, j.toString())
        return v.size
    }

    private val STIX = Regex("""(ipv4-addr:value|ipv6-addr:value|domain-name:value|url:value|app:id|process:name)\s*=\s*'([^']+)'""")
    private val NOMBRE = Regex("^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$")

    /** Acepta STIX2 (patrones «[domain-name:value = '…']») o una lista de texto con un indicador por línea. */
    fun extraer(texto: String): Set<String> {
        val res = LinkedHashSet<String>()
        fun anadir(crudo: String) {
            if (res.size >= MAX) return
            var t = crudo.trim().lowercase()
            if (t.startsWith("http://") || t.startsWith("https://")) t = UtilRed.extraerHost(t) ?: return
            if (t.length < 3 || t.length > 253) return
            if (UtilRed.esIpv4Valida(t)) {
                res.add(t)
            } else if (t.contains('.') && NOMBRE.matches(t)) {
                res.add(t)
            } else if (t.contains(':') && t.all { it in '0'..'9' || it in 'a'..'f' || it == ':' }) {
                res.add(t)
            }
        }
        for (m in STIX.findAll(texto)) {
            val tipo = m.groupValues[1]
            val valor = m.groupValues[2]
            if (tipo == "process:name") continue
            anadir(valor)
        }
        if (res.isEmpty() || !texto.contains("stix", ignoreCase = true)) {
            for (linea in texto.lines()) {
                val l = linea.substringBefore('#').trim()
                if (l.isEmpty() || l.contains(' ') || l.contains(',')) {
                    // Líneas con comas (CSV): se toma cada campo.
                    for (campo in l.split(',', ' ', '\t')) if (campo.isNotBlank()) anadir(campo)
                } else {
                    anadir(l)
                }
            }
        }
        return res
    }

    /** ¿Coincide [valor] (IP, dominio o paquete) con la lista? Los dominios también coinciden por sufijo. */
    fun coincide(valor: String?, lista: Set<String>): Boolean {
        if (valor == null || lista.isEmpty()) return false
        val v = valor.lowercase().trim('.')
        if (lista.contains(v)) return true
        if (!v.contains('.') || UtilRed.esIpv4Valida(v)) return false
        for (s in UtilRed.cadenaDeSufijos(v)) {
            if (s.contains('.') && lista.contains(s)) return true
        }
        return false
    }
}
