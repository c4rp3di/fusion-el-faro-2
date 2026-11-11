package com.vigia.faro

import android.content.Context
import com.vigia.core.seguridad.AlmacenClaves
import com.vigia.core.seguridad.PerdidaClave
import org.json.JSONObject

/**
 * Nombres que el usuario da a los equipos de la red y a los dispositivos Bluetooth, y marca de «conocido». Se guardan cifrados
 * con el Keystore. La clave es la MAC (o la IP si no se pudo leer la MAC: en ese caso el nombre puede quedar mal asociado si el router
 * reparte esa IP a otro equipo). Bluetooth usa su dirección, que en muchos dispositivos cambia con el tiempo.
 */
object Alias {
    private const val CLAVE = "alias_v1"
    private const val MAX = 500

    class Entrada(val nombre: String?, val confiable: Boolean)

    private fun almacen(c: Context) = AlmacenClaves.paraApp(c, "faro", PerdidaClave.REGENERAR_Y_BORRAR_BD)

    private fun leerTodo(c: Context): JSONObject {
        val t = almacen(c).leerSecreto(CLAVE) ?: return JSONObject()
        return try {
            JSONObject(t)
        } catch (e: Exception) {
            JSONObject()
        }
    }

    private fun claves(d: Dispositivo): List<String> {
        val l = ArrayList<String>()
        if (d.mac != null) l.add("mac:" + d.mac)
        l.add("ip:" + d.ip)
        return l
    }

    private fun entrada(raiz: JSONObject, clave: String): Entrada? {
        val o = raiz.optJSONObject(clave) ?: return null
        val n = o.optString("n", "")
        return Entrada(if (n.isEmpty()) null else n, o.optBoolean("c", false))
    }

    /** Pone [Dispositivo.alias] y [Dispositivo.confiable] a los equipos que el usuario ya nombró. */
    fun aplicar(c: Context, lista: List<Dispositivo>) {
        val raiz = leerTodo(c)
        for (d in lista) {
            for (k in claves(d)) {
                val e = entrada(raiz, k) ?: continue
                d.alias = e.nombre
                d.confiable = e.confiable
                break
            }
        }
    }

    private fun guardarClave(c: Context, clave: String, nombre: String?, confiable: Boolean) {
        val raiz = leerTodo(c)
        if (nombre.isNullOrBlank() && !confiable) {
            raiz.remove(clave)
        } else {
            raiz.put(clave, JSONObject().put("n", nombre?.trim() ?: "").put("c", confiable))
        }
        while (raiz.length() > MAX) {
            val k = raiz.keys().next()
            if (k == clave) break
            raiz.remove(k)
        }
        almacen(c).guardarSecreto(CLAVE, raiz.toString())
    }

    /** Guarda el nombre y la marca de un equipo de la red (con la MAC si la tiene; si no, con la IP). */
    fun guardar(c: Context, d: Dispositivo, nombre: String?, confiable: Boolean) {
        val clave = if (d.mac != null) "mac:" + d.mac else "ip:" + d.ip
        guardarClave(c, clave, nombre, confiable)
        d.alias = if (nombre.isNullOrBlank()) null else nombre.trim()
        d.confiable = confiable
    }

    // ------------------------------------------------------------------ Bluetooth

    fun obtenerBt(c: Context, direccion: String): Entrada? = entrada(leerTodo(c), "bt:" + direccion.uppercase())

    fun guardarBt(c: Context, direccion: String, nombre: String?, confiable: Boolean) {
        guardarClave(c, "bt:" + direccion.uppercase(), nombre, confiable)
    }
}
