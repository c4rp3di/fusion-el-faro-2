package com.vigia.faro.forense

import android.content.Context
import com.vigia.core.seguridad.AlmacenClaves
import com.vigia.core.seguridad.PerdidaClave
import org.json.JSONArray
import org.json.JSONObject

/**
 * Historial encadenado de los análisis forenses: cada entrada guarda el hash de su informe y el de la anterior, de modo
 * que quitar o cambiar una entrada rompe la cadena. Está cifrado con el Keystore (no es un registro a prueba de un atacante
 * con acceso total al teléfono: para eso sirve exportar la evidencia firmada y guardarla fuera).
 */
object Libro {
    private const val CLAVE = "libro_v1"
    private const val MAX = 200
    private val GENESIS = "0".repeat(64)

    class Entrada(val n: Int, val momento: Long, val red: String, val puntuacion: Int, val hash: String, val previo: String) {
        /** Vínculo con la entrada siguiente: sha256(previo + hash). */
        val enlace: String get() = Huellas.sha256(previo + hash)
    }

    private fun almacen(c: Context) = AlmacenClaves.paraApp(c, "faro", PerdidaClave.REGENERAR_Y_BORRAR_BD)

    fun cargar(c: Context): List<Entrada> {
        val texto = almacen(c).leerSecreto(CLAVE) ?: return emptyList()
        return try {
            val arr = JSONArray(texto)
            val res = ArrayList<Entrada>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                res.add(Entrada(o.getInt("n"), o.getLong("momento"), o.getString("red"), o.getInt("puntuacion"), o.getString("hash"), o.getString("previo")))
            }
            res
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun ultimoEnlace(c: Context): String = cargar(c).lastOrNull()?.enlace ?: GENESIS

    fun siguienteNumero(c: Context): Int = (cargar(c).lastOrNull()?.n ?: 0) + 1

    /** Añade una entrada. [previo] debe ser el valor de [ultimoEnlace] que se usó al construir el informe. */
    fun agregar(c: Context, n: Int, momento: Long, red: String, puntuacion: Int, hash: String, previo: String) {
        val lista = ArrayList(cargar(c))
        lista.add(Entrada(n, momento, red, puntuacion, hash, previo))
        while (lista.size > MAX) lista.removeAt(0)
        val arr = JSONArray()
        for (e in lista) {
            arr.put(
                JSONObject().put("n", e.n).put("momento", e.momento).put("red", e.red).put("puntuacion", e.puntuacion)
                    .put("hash", e.hash).put("previo", e.previo)
            )
        }
        almacen(c).guardarSecreto(CLAVE, arr.toString())
    }

    /** Devuelve el número de la primera entrada con la cadena rota, o null si está íntegra. */
    fun primeraRota(lista: List<Entrada>): Int? {
        for (i in 1 until lista.size) {
            if (lista[i].previo != lista[i - 1].enlace) return lista[i].n
        }
        return null
    }
}
