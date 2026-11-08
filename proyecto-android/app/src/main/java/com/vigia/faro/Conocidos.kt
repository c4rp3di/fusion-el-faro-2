package com.vigia.faro

import android.content.Context
import com.vigia.core.seguridad.AlmacenClaves
import com.vigia.core.seguridad.PerdidaClave
import org.json.JSONArray
import org.json.JSONObject

/** Recuerda qué dispositivos había en cada red, cifrado con el Keystore (AlmacenClaves del núcleo), para avisar de los nuevos. */
object Conocidos {
    private const val CLAVE = "redes_v1"

    private fun almacen(c: Context) = AlmacenClaves.paraApp(c, "faro", PerdidaClave.REGENERAR_Y_BORRAR_BD)

    /** Identificadores de la última visita a esta red, o null si es la primera vez. */
    fun cargar(c: Context, idRed: String): Set<String>? {
        val texto = almacen(c).leerSecreto(CLAVE) ?: return null
        return try {
            val arr = JSONObject(texto).optJSONArray(idRed) ?: return null
            val res = HashSet<String>()
            for (i in 0 until arr.length()) res.add(arr.getString(i))
            res
        } catch (e: Exception) {
            null
        }
    }

    fun guardar(c: Context, idRed: String, ids: Collection<String>) {
        val a = almacen(c)
        val raiz = try {
            JSONObject(a.leerSecreto(CLAVE) ?: "{}")
        } catch (e: Exception) {
            JSONObject()
        }
        val arr = JSONArray()
        for (id in ids) arr.put(id)
        raiz.put(idRed, arr)
        // Se recuerdan como mucho 30 redes.
        while (raiz.length() > 30) {
            val k = raiz.keys().next()
            if (k == idRed) break
            raiz.remove(k)
        }
        a.guardarSecreto(CLAVE, raiz.toString())
    }
}
