package com.vigia.faro

import android.Manifest
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.vigia.core.R
import com.vigia.core.ui.ActividadBase
import com.vigia.core.ui.Dialogos
import com.vigia.core.ui.TipoBoton
import com.vigia.core.ui.Vistas
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

class PrincipalActivity : ActividadBase() {

    private lateinit var textoRed: TextView
    private lateinit var botonCompleto: MaterialButton
    private lateinit var botonRouter: MaterialButton
    private lateinit var botonCancelar: MaterialButton
    private lateinit var botonUbicacion: MaterialButton
    private lateinit var textoProgreso: TextView
    private lateinit var resultados: LinearLayout

    private var trabajo: Job? = null
    private var ultimo: ResultadoAnalisis? = null

    private val pedirUbicacion = registerForActivityResult(ActivityResultContracts.RequestPermission()) { mostrarRed() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        construirUi()
    }

    override fun onResume() {
        super.onResume()
        mostrarRed()
    }

    private fun construirUi() {
        val raiz = Vistas.columna(this, 16)
        raiz.addView(Vistas.titulo(this, "El Faro"), Vistas.anchoCompleto(this, 2))
        raiz.addView(Vistas.texto(this, "Analiza la seguridad de la red Wi-Fi a la que estás conectado.", true), Vistas.anchoCompleto(this, 14))

        val tarjeta = Vistas.tarjeta(this)
        tarjeta.addView(Vistas.subtitulo(this, "Tu red"), Vistas.anchoCompleto(this, 6))
        textoRed = Vistas.texto(this, "")
        tarjeta.addView(textoRed, Vistas.anchoCompleto(this, 8))
        botonUbicacion = Vistas.boton(this, "Mostrar nombre y seguridad de la red", TipoBoton.TONAL) { pedirUbicacion.launch(Manifest.permission.ACCESS_FINE_LOCATION) }
        tarjeta.addView(botonUbicacion, Vistas.anchoCompleto(this, 0))
        raiz.addView(tarjeta, Vistas.anchoCompleto(this, 12))

        botonCompleto = Vistas.boton(this, "Análisis completo (router y dispositivos)") { iniciar(true) }
        raiz.addView(botonCompleto, Vistas.anchoCompleto(this, 6))
        botonRouter = Vistas.boton(this, "Solo router y red", TipoBoton.TONAL) { iniciar(false) }
        raiz.addView(botonRouter, Vistas.anchoCompleto(this, 6))
        botonCancelar = Vistas.boton(this, "Cancelar", TipoBoton.PELIGRO) { cancelar() }
        botonCancelar.visibility = View.GONE
        raiz.addView(botonCancelar, Vistas.anchoCompleto(this, 6))
        textoProgreso = Vistas.texto(this, "", true)
        raiz.addView(textoProgreso, Vistas.anchoCompleto(this, 12))

        resultados = LinearLayout(this)
        resultados.orientation = LinearLayout.VERTICAL
        raiz.addView(resultados, Vistas.anchoCompleto(this, 0))

        val scroll = ScrollView(this)
        scroll.addView(raiz)
        setContentView(scroll)
    }

    private fun mostrarRed() {
        val r = LectorRed.leer(this)
        val sb = StringBuilder()
        if (!r.conectada && !r.esWifi) {
            sb.append("Sin conexión a una red.")
        } else if (!r.esWifi) {
            sb.append("Estás usando datos móviles. El análisis de red local solo tiene sentido en una red Wi-Fi.")
        } else {
            sb.append("Wi-Fi: ").append(r.ssid ?: "(nombre oculto por Android)").append('\n')
            sb.append("Seguridad: ").append(r.seguridad.etiqueta).append('\n')
            sb.append("IP del teléfono: ").append(r.ipLocal ?: "?").append("/").append(r.prefijo).append('\n')
            sb.append("Router: ").append(r.gateway ?: "?").append('\n')
            sb.append("DNS: ").append(if (r.dns.isEmpty()) "?" else r.dns.joinToString(", "))
            if (r.portalMarcado) sb.append("\n⚠ Android la marca como red con portal cautivo.")
        }
        textoRed.text = sb.toString()
        botonUbicacion.visibility = if (r.faltaUbicacion) View.VISIBLE else View.GONE
        val puede = r.esWifi && r.gateway != null && r.ipLocal != null && trabajo?.isActive != true
        botonCompleto.isEnabled = puede
        botonRouter.isEnabled = puede
    }

    private fun iniciar(completo: Boolean) {
        val r = LectorRed.leer(this)
        if (!r.esWifi || r.gateway == null || r.ipLocal == null) {
            Dialogos.informar(this, "Sin Wi-Fi", "Conéctate a una red Wi-Fi para analizarla.")
            return
        }
        val publica = r.seguridad == Seguridad.ABIERTA || r.portalMarcado
        if (completo && publica) {
            Dialogos.confirmar(
                this, "Red pública",
                "Estás en una red abierta o con portal cautivo. Buscar y analizar los dispositivos de otras personas puede no estar permitido. " +
                    "Usa el análisis completo solo en TU red. ¿Continuar de todos modos?",
                "Continuar"
            ) { lanzar(r, true) }
        } else {
            lanzar(r, completo)
        }
    }

    private fun lanzar(red: InfoRed, completo: Boolean) {
        trabajo?.cancel()
        resultados.removeAllViews()
        botonCompleto.isEnabled = false
        botonRouter.isEnabled = false
        botonCancelar.visibility = View.VISIBLE
        trabajo = lifecycleScope.launch {
            try {
                val res = Orquestador.analizar(this@PrincipalActivity, red, completo) { texto ->
                    runOnUiThread { textoProgreso.text = texto }
                }
                ultimo = res
                textoProgreso.text = "Análisis terminado."
                mostrarResultado(res)
            } catch (e: CancellationException) {
                textoProgreso.text = "Análisis cancelado."
                throw e
            } catch (e: Exception) {
                textoProgreso.text = "Error: " + (e.message ?: e.javaClass.simpleName)
            } finally {
                botonCancelar.visibility = View.GONE
                mostrarRed()
            }
        }
    }

    private fun cancelar() {
        trabajo?.cancel()
    }

    // ------------------------------------------------------------------ resultados

    private fun colorRiesgo(r: Riesgo): Int {
        return when (r) {
            Riesgo.CRITICO -> Vistas.color(this, R.color.vc_peligro)
            Riesgo.ALTO -> Color.parseColor("#FB8C00")
            Riesgo.MEDIO -> Vistas.color(this, R.color.vc_aviso)
            Riesgo.BAJO -> Vistas.color(this, R.color.vc_texto_sec)
            Riesgo.INFO -> Vistas.color(this, R.color.vc_ok)
        }
    }

    private fun mostrarResultado(res: ResultadoAnalisis) {
        resultados.removeAllViews()

        val t = Vistas.tarjeta(this)
        val grande = Vistas.titulo(this, res.informe.puntuacion.toString() + " / 100  ·  " + res.informe.veredicto)
        grande.textSize = 26f
        val color = if (res.informe.puntuacion >= 85) R.color.vc_ok else if (res.informe.puntuacion >= 65) R.color.vc_aviso else R.color.vc_peligro
        grande.setTextColor(Vistas.color(this, color))
        t.addView(grande, Vistas.anchoCompleto(this, 4))
        t.addView(Vistas.texto(this, "Puntuación orientativa: resume lo que se pudo comprobar desde este teléfono. No es una auditoría completa.", true))
        resultados.addView(t, Vistas.anchoCompleto(this, 12))

        resultados.addView(Vistas.subtitulo(this, "Hallazgos"), Vistas.anchoCompleto(this, 6))
        for (h in res.informe.hallazgos) resultados.addView(tarjetaHallazgo(h), Vistas.anchoCompleto(this, 8))

        val router = res.router
        if (router != null) {
            resultados.addView(Vistas.subtitulo(this, "Router"), Vistas.anchoCompleto(this, 6))
            resultados.addView(tarjetaDispositivo(router), Vistas.anchoCompleto(this, 8))
        }
        val otros = res.dispositivos.filter { !it.esRouter }
        if (otros.isNotEmpty()) {
            resultados.addView(Vistas.subtitulo(this, "Dispositivos (" + otros.size + ")"), Vistas.anchoCompleto(this, 6))
            resultados.addView(
                Vistas.texto(this, "Solo aparecen los que responden. Muchos móviles en reposo no contestan, así que la lista puede estar incompleta.", true),
                Vistas.anchoCompleto(this, 8)
            )
            for (d in otros) resultados.addView(tarjetaDispositivo(d), Vistas.anchoCompleto(this, 8))
        }

        resultados.addView(Vistas.boton(this, "Compartir informe", TipoBoton.TONAL) { compartir(res) }, Vistas.anchoCompleto(this, 0))
    }

    private fun tarjetaHallazgo(h: Hallazgo): LinearLayout {
        val t = Vistas.tarjeta(this)
        val cab = Vistas.texto(this, h.riesgo.etiqueta.uppercase() + "  ·  " + h.titulo)
        cab.setTypeface(cab.typeface, Typeface.BOLD)
        cab.setTextColor(colorRiesgo(h.riesgo))
        t.addView(cab, Vistas.anchoCompleto(this, 4))
        t.addView(Vistas.texto(this, h.detalle), Vistas.anchoCompleto(this, 4))
        if (h.riesgo != Riesgo.INFO) t.addView(Vistas.texto(this, "Qué hacer: " + h.accion, true))
        return t
    }

    private fun tarjetaDispositivo(d: Dispositivo): LinearLayout {
        val t = Vistas.tarjeta(this)
        val etiqueta = d.tipo.icono + "  " + d.nombreVisible + (if (d.nuevo) "   ● NUEVO" else "")
        val nombre = Vistas.texto(this, etiqueta)
        nombre.setTypeface(nombre.typeface, Typeface.BOLD)
        nombre.textSize = 15f
        if (d.nuevo) nombre.setTextColor(Vistas.color(this, R.color.vc_aviso))
        t.addView(nombre)
        val sub = StringBuilder(d.ip).append(" · ").append(d.tipo.etiqueta)
        if (d.mac != null) sub.append(" · ").append(d.mac)
        t.addView(Vistas.texto(this, sub.toString(), true))
        if (d.puertos.isEmpty()) {
            t.addView(Vistas.texto(this, "Ningún puerto del catálogo abierto.", true))
        } else {
            for (p in d.puertos) {
                val linea = Vistas.texto(this, "• " + p.def.puerto + " " + p.def.servicio + (if (p.banner != null) " — " + p.banner else "") + "  [" + p.def.riesgo.etiqueta + "]")
                linea.setTextColor(colorRiesgo(p.def.riesgo))
                linea.textSize = 12f
                t.addView(linea)
            }
        }
        t.setOnClickListener { detalle(d) }
        return t
    }

    private fun detalle(d: Dispositivo) {
        val sb = StringBuilder()
        sb.append("IP: ").append(d.ip).append('\n')
        if (d.mac != null) sb.append("MAC: ").append(d.mac).append('\n')
        if (d.fabricante != null) sb.append("Fabricante: ").append(d.fabricante).append('\n')
        if (d.modelo != null) sb.append("Modelo: ").append(d.modelo).append('\n')
        if (d.servicios.isNotEmpty()) sb.append("\nServicios anunciados:\n").append(d.servicios.joinToString("\n") { "· " + it }).append('\n')
        if (d.puertos.isNotEmpty()) {
            sb.append("\nPuertos abiertos:\n")
            for (p in d.puertos) sb.append("· ").append(p.def.puerto).append(' ').append(p.def.servicio).append(": ").append(p.def.nota).append('\n')
        }
        if (d.mac == null) sb.append("\nSin dirección MAC: Android 10+ no la deja leer a las apps.")
        Dialogos.informar(this, d.nombreVisible, sb.toString())
    }

    private fun compartir(res: ResultadoAnalisis) {
        val texto = Analisis.texto(res.red, res.informe, res.router, res.dispositivos.filter { !it.esRouter })
        val i = Intent(Intent.ACTION_SEND)
        i.type = "text/plain"
        i.putExtra(Intent.EXTRA_SUBJECT, "Informe de seguridad de red · El Faro")
        i.putExtra(Intent.EXTRA_TEXT, texto)
        startActivity(Intent.createChooser(i, "Compartir informe"))
    }
}
