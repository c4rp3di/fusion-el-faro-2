package com.vigia.faro.forense

import android.content.Context
import android.net.Uri
import android.os.Build
import androidx.core.content.FileProvider
import com.vigia.core.util.Formato
import com.vigia.faro.Dispositivo
import com.vigia.faro.ResultadoAnalisis
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Paquete de evidencia: el informe completo en JSON (hallazgos, equipos, secciones y las salidas crudas de cada
 * comprobación con su hash SHA-256), firmado con una clave del Keystore de este teléfono. Quien lo reciba puede comprobar
 * que no se modificó (firma y hashes) y de qué teléfono salió (huella de la clave pública).
 */
object Evidencia {

    private fun dispositivo(d: Dispositivo): JSONObject {
        val puertos = JSONArray()
        for (p in d.puertos) {
            puertos.put(
                JSONObject().put("puerto", p.def.puerto).put("servicio", p.def.servicio).put("riesgo", p.def.riesgo.etiqueta)
                    .put("banner", p.banner ?: JSONObject.NULL)
            )
        }
        return JSONObject()
            .put("ip", d.ip)
            .put("mac", d.mac ?: JSONObject.NULL)
            .put("mac_aleatoria", com.vigia.faro.forense.Oui.esAleatoria(d.mac))
            .put("fabricante", d.fabricante ?: JSONObject.NULL)
            .put("modelo", d.modelo ?: JSONObject.NULL)
            .put("nombre", d.nombre ?: JSONObject.NULL)
            .put("alias", d.alias ?: JSONObject.NULL)
            .put("confiable", d.confiable)
            .put("ipv6", JSONArray(d.ipv6.toList()))
            .put("tipo", d.tipo.etiqueta)
            .put("es_router", d.esRouter)
            .put("es_este_telefono", d.esEsteTelefono)
            .put("nuevo", d.nuevo)
            .put("certificado", d.certificado ?: JSONObject.NULL)
            .put("servicios", JSONArray(d.servicios.toList()))
            .put("puertos", puertos)
    }

    /** Texto JSON del informe. Es el texto que se firma, así que no debe cambiar entre la generación y la exportación. */
    fun contenido(c: Context, res: ResultadoAnalisis, n: Int, previo: String): String {
        val version = try {
            c.packageManager.getPackageInfo(c.packageName, 0).versionName ?: "?"
        } catch (e: Exception) {
            "?"
        }
        val r = res.red
        val j = JSONObject()
        j.put("tipo", "faro-informe")
        j.put("generado", res.momento)
        j.put("app", JSONObject().put("nombre", "El Faro").put("version", version))
        j.put(
            "dispositivo",
            JSONObject().put("fabricante", Build.MANUFACTURER).put("modelo", Build.MODEL).put("android", Build.VERSION.RELEASE)
                .put("sdk", Build.VERSION.SDK_INT).put("parche", Build.VERSION.SECURITY_PATCH)
        )
        j.put(
            "red",
            JSONObject().put("ssid", r.ssid ?: JSONObject.NULL).put("bssid", r.bssid ?: JSONObject.NULL).put("seguridad", r.seguridad.etiqueta)
                .put("ip", r.ipLocal ?: JSONObject.NULL).put("prefijo", r.prefijo).put("router", r.gateway ?: JSONObject.NULL)
                .put("dns", JSONArray(r.dns)).put("portal_android", r.portalMarcado).put("portal_prueba", res.portal.estado.name)
        )
        j.put("puntuacion", res.informe.puntuacion)
        j.put("veredicto", res.informe.veredicto)
        j.put("completo", res.completo)

        val hallazgos = JSONArray()
        for (h in res.informe.hallazgos) {
            hallazgos.put(
                JSONObject().put("riesgo", h.riesgo.etiqueta).put("titulo", h.titulo).put("detalle", h.detalle).put("accion", h.accion)
                    .put("fuente", h.fuente)
            )
        }
        j.put("hallazgos", hallazgos)

        val equipos = JSONArray()
        val router = res.router
        if (router != null) equipos.put(dispositivo(router))
        for (d in res.dispositivos) if (d !== router) equipos.put(dispositivo(d))
        j.put("equipos", equipos)

        val f = res.forense
        if (f != null) {
            val secciones = JSONArray()
            for (s in f.secciones) secciones.put(JSONObject().put("titulo", s.titulo).put("lineas", JSONArray(s.lineas)))
            j.put("secciones", secciones)
            j.put("limitaciones", JSONArray(f.limitaciones))
            j.put("adb_usado", f.adbUsado)
            j.put("indicadores_cargados", f.indicadoresCargados)
            val artefactos = JSONArray()
            for (a in f.artefactos) {
                artefactos.put(
                    JSONObject().put("id", a.id).put("orden", a.orden).put("momento", a.momento).put("bytes_originales", a.bytesOriginales)
                        .put("truncado", a.truncado).put("sha256", a.sha256).put("contenido", a.contenido)
                )
            }
            j.put("artefactos", artefactos)
        }
        j.put("cadena", JSONObject().put("n", n).put("previo", previo))
        return j.toString()
    }

    /** Guarda el paquete firmado en la caché de la app y devuelve su URI para compartirlo. */
    fun exportar(c: Context, res: ResultadoAnalisis): Uri = exportarContenido(c, "faro-evidencia", res.momento, res.evidencia)

    /** Firma [contenido] (un texto JSON) y lo guarda como «prefijo-fecha.json» en la caché de la app. */
    fun exportarContenido(c: Context, prefijo: String, momento: Long, contenido: String): Uri {
        val sobre = Firma.sobre(contenido)
        val dir = File(c.cacheDir, "evidencia")
        dir.mkdirs()
        val viejos = dir.listFiles()
        if (viejos != null) for (v in viejos) v.delete()
        val nombre = prefijo + "-" + SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date(momento)) + ".json"
        val f = File(dir, nombre)
        f.writeText(sobre.toString(2), Charsets.UTF_8)
        return FileProvider.getUriForFile(c, c.packageName + ".archivos", f)
    }

    class Verificacion(val firmaValida: Boolean, val texto: String)

    fun verificar(c: Context, archivo: String): Verificacion {
        val sobre = try {
            JSONObject(archivo)
        } catch (e: Exception) {
            return Verificacion(false, "El archivo no es un JSON válido.")
        }
        if (sobre.optString("formato") != Firma.FORMATO) return Verificacion(false, "No es un paquete de evidencia de El Faro.")
        val v = Firma.verificar(sobre)
        val sb = StringBuilder()
        sb.append("FIRMA: ").append(if (v.valida) "VÁLIDA" else "NO VÁLIDA (el contenido pudo ser modificado)").append('\n')
        if (v.valida) {
            sb.append("Firmada por la clave ").append(v.huellaClave).append(": ")
                .append(if (v.esDeEsteTelefono) "este teléfono." else "otro teléfono (no se generó aquí).").append('\n')
        }
        try {
            val texto = sobre.getString("contenido")
            val hash = Huellas.sha256(texto)
            sb.append("Huella del contenido (SHA-256): ").append(hash.take(32)).append("…\n")
            val cont = JSONObject(texto)
            sb.append("Generado: ").append(Formato.fechaHoraCompleta(cont.optLong("generado"))).append('\n')
            val dispo = cont.optJSONObject("dispositivo")
            if (dispo != null) sb.append("Teléfono: ").append(dispo.optString("fabricante")).append(' ').append(dispo.optString("modelo")).append(" · Android ").append(dispo.optString("android")).append('\n')
            val red = cont.optJSONObject("red")
            if (red != null) sb.append("Red: ").append(red.optString("ssid", "(oculta)")).append(" · router ").append(red.optString("router")).append('\n')
            sb.append("Puntuación: ").append(cont.optInt("puntuacion")).append("/100 (").append(cont.optString("veredicto")).append(")\n")
            val hall = cont.optJSONArray("hallazgos")
            if (hall != null) {
                val cuenta = HashMap<String, Int>()
                for (i in 0 until hall.length()) {
                    val r = hall.getJSONObject(i).optString("riesgo")
                    cuenta[r] = (cuenta[r] ?: 0) + 1
                }
                sb.append("Hallazgos: ").append(hall.length()).append(" (").append(cuenta.entries.joinToString(", ") { it.key + " " + it.value }).append(")\n")
            }
            val arts = cont.optJSONArray("artefactos")
            if (arts != null) {
                var ok = 0
                val mal = ArrayList<String>()
                for (i in 0 until arts.length()) {
                    val a = arts.getJSONObject(i)
                    if (Huellas.sha256(a.getString("contenido")) == a.getString("sha256")) ok++ else mal.add(a.optString("id"))
                }
                sb.append("Pruebas crudas: ").append(arts.length()).append(" · hashes correctos: ").append(ok)
                if (mal.isNotEmpty()) sb.append(" · ALTERADAS: ").append(mal.joinToString(", "))
                sb.append('\n')
            }
            val cadena = cont.optJSONObject("cadena")
            if (cadena != null) {
                sb.append("Entrada n.º ").append(cadena.optInt("n")).append(" del historial del teléfono emisor.\n")
                val local = Libro.cargar(c).firstOrNull { it.hash == hash }
                sb.append(if (local != null) "Coincide con la entrada n.º " + local.n + " del historial de este teléfono.\n" else "No figura en el historial de este teléfono.\n")
            }
        } catch (e: Exception) {
            sb.append("No se pudo leer el contenido del informe.")
        }
        return Verificacion(v.valida, sb.toString())
    }
}
