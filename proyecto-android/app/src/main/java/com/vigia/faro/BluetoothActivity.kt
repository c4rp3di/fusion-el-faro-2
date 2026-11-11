package com.vigia.faro

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.vigia.core.R
import com.vigia.core.ui.ActividadBase
import com.vigia.core.ui.Dialogos
import com.vigia.core.ui.TipoBoton
import com.vigia.core.ui.Vistas
import com.vigia.faro.bt.AnalisisBt
import com.vigia.faro.bt.DispositivoBt
import com.vigia.faro.bt.Fabricantes
import com.vigia.faro.bt.InformeBt
import com.vigia.faro.bt.ResultadoBt
import com.vigia.faro.bt.ScannerBt
import com.vigia.faro.forense.Evidencia
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build

/** Análisis puntual de Bluetooth: qué hay a tu alrededor, posibles rastreadores y cómo está expuesto el teléfono. */
class BluetoothActivity : ActividadBase() {

    private lateinit var botonAnalizar: MaterialButton
    private lateinit var textoProgreso: TextView
    private lateinit var resultados: LinearLayout

    private var trabajo: Job? = null
    private var ultimo: ResultadoBt? = null
    private var informe: InformeBt? = null

    private val pedirPermisos = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        if (ScannerBt.tienePermisos(this)) {
            analizar()
        } else {
            Toast.makeText(this, "Sin esos permisos Android no deja escanear Bluetooth.", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val raiz = Vistas.columna(this, 16)
        raiz.addView(Vistas.titulo(this, "Análisis Bluetooth"), Vistas.anchoCompleto(this, 2))
        raiz.addView(
            Vistas.texto(
                this,
                "Escucha unos 20 segundos los dispositivos Bluetooth de alrededor (de bajo consumo y clásicos) y los que ya tienes emparejados. " +
                    "Detecta posibles rastreadores (AirTag, SmartTag, Tile), si tu teléfono es visible para todos y qué dispositivos emparejados conserva. " +
                    "No se conecta a ningún dispositivo. Android pide el permiso de ubicación para poder escanear Bluetooth: El Faro no calcula ni guarda tu posición.",
                true
            ),
            Vistas.anchoCompleto(this, 12)
        )
        botonAnalizar = Vistas.boton(this, "Analizar Bluetooth") { empezar() }
        raiz.addView(botonAnalizar, Vistas.anchoCompleto(this, 8))
        textoProgreso = Vistas.texto(this, "", true)
        raiz.addView(textoProgreso, Vistas.anchoCompleto(this, 8))
        resultados = Vistas.columna(this, 0)
        raiz.addView(resultados)
        val scroll = ScrollView(this)
        scroll.addView(raiz)
        setContentView(scroll)
    }

    private fun empezar() {
        if (ScannerBt.tienePermisos(this)) analizar() else pedirPermisos.launch(ScannerBt.permisos())
    }

    private fun analizar() {
        trabajo?.cancel()
        resultados.removeAllViews()
        botonAnalizar.isEnabled = false
        trabajo = lifecycleScope.launch {
            try {
                val res = ScannerBt.escanear(this@BluetoothActivity) { t -> runOnUiThread { textoProgreso.text = t } }
                when {
                    res.sinBluetooth -> textoProgreso.text = "Este teléfono no tiene Bluetooth."
                    res.faltanPermisos -> textoProgreso.text = "Faltan permisos para escanear Bluetooth."
                    res.apagado -> textoProgreso.text = "El Bluetooth está apagado. Actívalo y vuelve a analizar (El Faro no lo enciende por ti)."
                    else -> {
                        val inf = AnalisisBt.analizar(res)
                        ultimo = res
                        informe = inf
                        textoProgreso.text = "Análisis terminado: " + res.dispositivos.size + " dispositivos."
                        mostrar(res, inf)
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                textoProgreso.text = "Error: " + (e.message ?: e.javaClass.simpleName)
            } finally {
                botonAnalizar.isEnabled = true
            }
        }
    }

    private fun colorRiesgo(r: Riesgo): Int {
        return when (r) {
            Riesgo.CRITICO -> Vistas.color(this, R.color.vc_peligro)
            Riesgo.ALTO -> Color.parseColor("#FB8C00")
            Riesgo.MEDIO -> Vistas.color(this, R.color.vc_aviso)
            Riesgo.BAJO -> Vistas.color(this, R.color.vc_texto_sec)
            Riesgo.INFO -> Vistas.color(this, R.color.vc_ok)
        }
    }

    private fun mostrar(res: ResultadoBt, inf: InformeBt) {
        resultados.removeAllViews()
        val t = Vistas.tarjeta(this)
        val grande = Vistas.titulo(this, inf.puntuacion.toString() + " / 100  ·  " + inf.veredicto)
        grande.textSize = 24f
        val color = if (inf.puntuacion >= 85) R.color.vc_ok else if (inf.puntuacion >= 65) R.color.vc_aviso else R.color.vc_peligro
        grande.setTextColor(Vistas.color(this, color))
        t.addView(grande, Vistas.anchoCompleto(this, 4))
        t.addView(
            Vistas.texto(
                this,
                "Tu teléfono: " + (res.nombreTelefono ?: "?") + " · visible para todos: " + (if (res.visible == null) "?" else if (res.visible) "sí" else "no"),
                true
            )
        )
        resultados.addView(t, Vistas.anchoCompleto(this, 12))

        resultados.addView(Vistas.subtitulo(this, "Hallazgos"), Vistas.anchoCompleto(this, 6))
        for (h in inf.hallazgos) resultados.addView(tarjetaHallazgo(h), Vistas.anchoCompleto(this, 8))

        resultados.addView(Vistas.subtitulo(this, "Dispositivos (" + res.dispositivos.size + ")"), Vistas.anchoCompleto(this, 6))
        resultados.addView(
            Vistas.texto(this, "Toca uno para ver su detalle, darle un nombre o marcarlo como conocido. Muchos cambian su dirección con el tiempo, así que el nombre puede no reconocerse la próxima vez.", true),
            Vistas.anchoCompleto(this, 8)
        )
        for (x in res.dispositivos) resultados.addView(tarjetaDispositivo(x), Vistas.anchoCompleto(this, 8))

        resultados.addView(Vistas.boton(this, "Compartir informe (texto)", TipoBoton.TONAL) { Acciones.compartir(this, "Análisis Bluetooth · El Faro", AnalisisBt.texto(res, inf)) }, Vistas.anchoCompleto(this, 6))
        resultados.addView(Vistas.boton(this, "Exportar evidencia firmada") { exportar(res, inf) }, Vistas.anchoCompleto(this, 0))
    }

    private fun tarjetaHallazgo(h: Hallazgo): LinearLayout {
        val t = Vistas.tarjeta(this)
        val cab = Vistas.texto(this, h.riesgo.etiqueta.uppercase() + "  ·  " + h.titulo)
        cab.setTypeface(cab.typeface, Typeface.BOLD)
        cab.setTextColor(colorRiesgo(h.riesgo))
        t.addView(cab, Vistas.anchoCompleto(this, 4))
        t.addView(Vistas.texto(this, h.detalle), Vistas.anchoCompleto(this, 4))
        if (h.riesgo != Riesgo.INFO) t.addView(Vistas.texto(this, "Qué hacer: " + h.accion, true))
        t.setOnClickListener {
            val msg = h.detalle + (if (h.riesgo != Riesgo.INFO) "\n\nQué hacer: " + h.accion else "")
            val acc = ArrayList<Pair<String, () -> Unit>>()
            acc.add(accion("Abrir ajustes de Bluetooth") { Acciones.lanzar(this, AccionSistema("", Intent(Settings.ACTION_BLUETOOTH_SETTINGS))) })
            acc.add(accion("Copiar") { Acciones.copiar(this, h.titulo + "\n" + msg) })
            acc.add(accion("Compartir") { Acciones.compartir(this, "Hallazgo · El Faro", h.titulo + "\n" + msg) })
            dialogo(h.riesgo.etiqueta.uppercase() + " · " + h.titulo, msg, acc)
        }
        return t
    }

    private fun tarjetaDispositivo(x: DispositivoBt): LinearLayout {
        val t = Vistas.tarjeta(this)
        val nombre = Vistas.texto(this, x.icono + "  " + x.nombreVisible + (if (x.confiable) "   ✓" else "") + (if (x.rastreador != null) "   ● RASTREADOR" else ""))
        nombre.setTypeface(nombre.typeface, Typeface.BOLD)
        nombre.textSize = 15f
        if (x.rastreador != null) nombre.setTextColor(Vistas.color(this, R.color.vc_aviso))
        t.addView(nombre)
        val sub = StringBuilder(x.direccion).append(" · ").append(x.tipoRadio)
        if (x.rssi != null) sub.append(" · ").append(x.rssi).append(" dBm")
        if (x.cercania != null) sub.append(" (").append(x.cercania).append(")")
        if (x.emparejado) sub.append(" · emparejado")
        t.addView(Vistas.texto(this, sub.toString(), true))
        val f = Fabricantes.nombre(x.fabricanteId)
        if (f != null) {
            val tf = Vistas.texto(this, "Fabricante: " + f, true)
            tf.textSize = 12f
            t.addView(tf)
        }
        t.setOnClickListener { detalle(x) }
        return t
    }

    private fun accion(etiqueta: String, f: () -> Unit): Pair<String, () -> Unit> = Pair(etiqueta, f)

    private fun dialogo(titulo: String, mensaje: String, acciones: List<Pair<String, () -> Unit>>) {
        val b = MaterialAlertDialogBuilder(this).setTitle(titulo).setMessage(mensaje).setNegativeButton("Cerrar", null)
        if (acciones.isNotEmpty()) {
            b.setPositiveButton("Acciones…") { _, _ ->
                Dialogos.elegir(this, titulo, acciones.map { it.first }) { i -> acciones[i].second() }
            }
        }
        b.show()
    }

    private fun detalle(x: DispositivoBt) {
        val sb = StringBuilder()
        if (x.alias != null) sb.append("Nombre que le diste: ").append(x.alias).append('\n')
        if (x.nombre != null) sb.append("Nombre que anuncia: ").append(x.nombre).append('\n')
        sb.append("Dirección: ").append(x.direccion).append('\n')
        sb.append("Tipo: ").append(x.tipoRadio).append('\n')
        if (x.clase != null) sb.append("Clase: ").append(x.clase).append('\n')
        val f = Fabricantes.nombre(x.fabricanteId)
        if (f != null) sb.append("Fabricante (según sus anuncios): ").append(f).append('\n')
        if (x.rssi != null) sb.append("Señal: ").append(x.rssi).append(" dBm").append(if (x.cercania != null) " (" + x.cercania + ")" else "").append('\n')
        if (x.txPower != null) sb.append("Potencia de transmisión anunciada: ").append(x.txPower).append(" dBm\n")
        if (x.conectable != null) sb.append("Acepta conexiones: ").append(if (x.conectable == true) "sí" else "no").append('\n')
        if (x.emparejado) sb.append("Emparejado con este teléfono.\n")
        if (x.rastreador != null) sb.append("\nParece un rastreador: ").append(x.rastreador).append(". Un análisis puntual no puede saber si te sigue.\n")
        if (x.uuids.isNotEmpty()) sb.append("\nServicios anunciados: ").append(x.uuids.take(12).joinToString(", ")).append('\n')
        sb.append("\nMuchos dispositivos usan una dirección aleatoria que cambia: el nombre que le des puede no reconocerse la próxima vez.")
        val acc = ArrayList<Pair<String, () -> Unit>>()
        acc.add(accion("Renombrar…") {
            Dialogos.pedirTexto(this, "Nombre del dispositivo", x.alias ?: x.nombreVisible, false, "Guardar") { texto ->
                Alias.guardarBt(this, x.direccion, texto, x.confiable || texto.isNotBlank())
                x.alias = if (texto.isBlank()) null else texto.trim()
                x.confiable = x.confiable || texto.isNotBlank()
                refrescar()
            }
        })
        acc.add(accion(if (x.confiable) "Quitar la marca de conocido" else "Marcar como conocido") {
            x.confiable = !x.confiable
            Alias.guardarBt(this, x.direccion, x.alias, x.confiable)
            refrescar()
        })
        acc.add(accion("Copiar dirección") { Acciones.copiar(this, x.direccion) })
        acc.add(accion("Abrir ajustes de Bluetooth") { Acciones.lanzar(this, AccionSistema("", Intent(Settings.ACTION_BLUETOOTH_SETTINGS))) })
        dialogo(x.nombreVisible, sb.toString(), acc)
    }

    /** Vuelve a calcular los hallazgos (un dispositivo «conocido» deja de contar como rastreador) y repinta. */
    private fun refrescar() {
        val r = ultimo ?: return
        val inf = AnalisisBt.analizar(r)
        informe = inf
        mostrar(r, inf)
    }

    private fun contenidoJson(res: ResultadoBt, inf: InformeBt): String {
        val j = JSONObject()
        j.put("tipo", "faro-bluetooth")
        j.put("generado", res.momento)
        j.put("dispositivo", JSONObject().put("fabricante", Build.MANUFACTURER).put("modelo", Build.MODEL).put("android", Build.VERSION.RELEASE))
        j.put("adaptador", JSONObject().put("nombre", res.nombreTelefono ?: JSONObject.NULL).put("visible", res.visible ?: JSONObject.NULL))
        j.put("puntuacion", inf.puntuacion)
        j.put("veredicto", inf.veredicto)
        val hs = JSONArray()
        for (h in inf.hallazgos) hs.put(JSONObject().put("riesgo", h.riesgo.etiqueta).put("titulo", h.titulo).put("detalle", h.detalle).put("accion", h.accion))
        j.put("hallazgos", hs)
        val ds = JSONArray()
        for (x in res.dispositivos) {
            ds.put(
                JSONObject().put("direccion", x.direccion).put("nombre", x.nombre ?: JSONObject.NULL).put("alias", x.alias ?: JSONObject.NULL)
                    .put("tipo", x.tipoRadio).put("rssi", x.rssi ?: JSONObject.NULL).put("emparejado", x.emparejado)
                    .put("fabricante", Fabricantes.nombre(x.fabricanteId) ?: JSONObject.NULL).put("conectable", x.conectable ?: JSONObject.NULL)
                    .put("rastreador", x.rastreador ?: JSONObject.NULL).put("servicios", JSONArray(x.uuids.toList()))
            )
        }
        j.put("dispositivos", ds)
        return j.toString()
    }

    private fun exportar(res: ResultadoBt, inf: InformeBt) {
        Dialogos.confirmar(
            this, "Exportar evidencia firmada",
            "El paquete incluye las direcciones y nombres de los dispositivos Bluetooth de tu entorno. Está firmado para que no se pueda cambiar sin que se note, pero NO está cifrado. Compártelo solo con quien deba verlo.",
            "Exportar"
        ) {
            lifecycleScope.launch {
                try {
                    val uri = withContext(Dispatchers.IO) { Evidencia.exportarContenido(this@BluetoothActivity, "faro-bluetooth", res.momento, contenidoJson(res, inf)) }
                    val i = Intent(Intent.ACTION_SEND)
                    i.type = "application/json"
                    i.putExtra(Intent.EXTRA_STREAM, uri)
                    i.putExtra(Intent.EXTRA_SUBJECT, "Evidencia Bluetooth firmada · El Faro")
                    i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    startActivity(Intent.createChooser(i, "Exportar evidencia"))
                } catch (e: Exception) {
                    Dialogos.informar(this@BluetoothActivity, "No se pudo exportar", e.message ?: e.javaClass.simpleName)
                }
            }
        }
    }
}
