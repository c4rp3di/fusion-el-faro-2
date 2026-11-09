package com.vigia.faro.forense

import android.content.Context
import com.vigia.core.seguridad.AlmacenClaves
import com.vigia.core.seguridad.PerdidaClave
import com.vigia.core.util.Formato
import com.vigia.faro.CatalogoPuertos
import com.vigia.faro.Riesgo
import org.json.JSONArray
import org.json.JSONObject

/**
 * Recuerda, cifrado con el Keystore, cómo era cada red la última vez (MAC del router, DNS, puertos del router, reenvíos UPnP)
 * y señala los cambios. Un cambio entre dos visitas es una de las pruebas más útiles para detectar un router manipulado.
 */
object LineaBase {
    private const val CLAVE = "base_v2"

    class Estado(
        val macRouter: String?,
        val dns: List<String>,
        val puertosRouter: List<Int>,
        val reenvios: List<String>,
        val macs: List<String>,
        val momento: Long
    )

    private fun almacen(c: Context) = AlmacenClaves.paraApp(c, "faro", PerdidaClave.REGENERAR_Y_BORRAR_BD)

    private fun lista(a: JSONArray?): List<String> {
        val r = ArrayList<String>()
        if (a != null) for (i in 0 until a.length()) r.add(a.getString(i))
        return r
    }

    fun cargar(c: Context, idRed: String): Estado? {
        val texto = almacen(c).leerSecreto(CLAVE) ?: return null
        return try {
            val o = JSONObject(texto).optJSONObject(idRed) ?: return null
            Estado(
                macRouter = if (o.has("mac_router")) o.getString("mac_router") else null,
                dns = lista(o.optJSONArray("dns")),
                puertosRouter = lista(o.optJSONArray("puertos")).mapNotNull { it.toIntOrNull() },
                reenvios = lista(o.optJSONArray("reenvios")),
                macs = lista(o.optJSONArray("macs")),
                momento = o.optLong("momento")
            )
        } catch (e: Exception) {
            null
        }
    }

    fun guardar(c: Context, idRed: String, e: Estado) {
        val a = almacen(c)
        val raiz = try {
            JSONObject(a.leerSecreto(CLAVE) ?: "{}")
        } catch (x: Exception) {
            JSONObject()
        }
        val o = JSONObject()
        if (e.macRouter != null) o.put("mac_router", e.macRouter)
        o.put("dns", JSONArray(e.dns))
        o.put("puertos", JSONArray(e.puertosRouter.map { it.toString() }))
        o.put("reenvios", JSONArray(e.reenvios))
        o.put("macs", JSONArray(e.macs))
        o.put("momento", e.momento)
        raiz.put(idRed, o)
        while (raiz.length() > 30) {
            val k = raiz.keys().next()
            if (k == idRed) break
            raiz.remove(k)
        }
        a.guardarSecreto(CLAVE, raiz.toString())
    }

    /** Compara con la visita anterior y añade los cambios como hallazgos y como sección. */
    fun comparar(datos: DatosForenses, antes: Estado, ahora: Estado) {
        val lineas = ArrayList<String>()
        lineas.add("Última visita: " + Formato.fecha(antes.momento))

        if (antes.macRouter != null && ahora.macRouter != null) {
            if (antes.macRouter != ahora.macRouter) {
                lineas.add("MAC del router: " + antes.macRouter + " → " + ahora.macRouter)
                datos.hallazgo(
                    Riesgo.ALTO, "La MAC del router cambió desde la última visita",
                    "Antes era " + antes.macRouter + " y ahora " + ahora.macRouter + ", con la misma IP y la misma red Wi-Fi. Pasa si cambiaste de router; también si otro equipo se hace pasar por él (ARP spoofing).",
                    "Si no cambiaste el router, no uses esta red para datos sensibles y revisa qué equipo es " + ahora.macRouter + ".", "Cambios"
                )
            } else {
                lineas.add("MAC del router: sin cambios")
            }
        }
        val dnsNuevos = ahora.dns.filter { !antes.dns.contains(it) }
        if (dnsNuevos.isNotEmpty()) {
            lineas.add("DNS: antes " + antes.dns.joinToString(",") + " · ahora " + ahora.dns.joinToString(","))
            datos.hallazgo(
                Riesgo.MEDIO, "Los servidores DNS cambiaron desde la última visita",
                "Antes: " + (if (antes.dns.isEmpty()) "ninguno" else antes.dns.joinToString(", ")) + ". Ahora: " + ahora.dns.joinToString(", ") + ". Un DNS cambiado sin motivo es la forma más común de redirigir el tráfico de una red.",
                "Si no lo cambiaste tú ni tu operador, revisa la configuración del router.", "Cambios"
            )
        }
        val puertosNuevos = ahora.puertosRouter.filter { !antes.puertosRouter.contains(it) }
        for (p in puertosNuevos) {
            val def = CatalogoPuertos.TODOS.firstOrNull { it.puerto == p } ?: continue
            if (def.riesgo.ordinal > Riesgo.MEDIO.ordinal) continue
            lineas.add("Puerto nuevo en el router: " + p + " " + def.servicio)
            datos.hallazgo(
                if (def.riesgo.ordinal <= Riesgo.ALTO.ordinal) Riesgo.ALTO else Riesgo.MEDIO,
                "Nuevo puerto abierto en el router: " + p + " (" + def.servicio + ")",
                "En la visita anterior estaba cerrado. " + def.nota,
                "Averigua quién lo abrió (actualización del router, el operador o un cambio no autorizado).", "Cambios"
            )
        }
        val reenviosNuevos = ahora.reenvios.filter { !antes.reenvios.contains(it) }
        if (reenviosNuevos.isNotEmpty()) {
            lineas.add("Reenvíos UPnP nuevos: " + reenviosNuevos.joinToString("; "))
            datos.hallazgo(
                Riesgo.MEDIO, reenviosNuevos.size.toString() + " reenvío(s) UPnP nuevo(s) desde la última visita",
                reenviosNuevos.take(5).joinToString("; ") + ".",
                "Comprueba que los abrió una app tuya (consola, videollamada…).", "Cambios"
            )
        }
        val desaparecidos = antes.macs.count { !ahora.macs.contains(it) }
        if (antes.macs.isNotEmpty() && ahora.macs.isNotEmpty()) lineas.add("Equipos que ya no responden: " + desaparecidos)
        datos.seccion("Cambios desde la visita anterior", lineas)
    }
}
