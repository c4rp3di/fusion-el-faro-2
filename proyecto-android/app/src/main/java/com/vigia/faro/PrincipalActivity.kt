package com.vigia.faro

import android.Manifest
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.vigia.core.R
import com.vigia.core.ui.ActividadBase
import com.vigia.core.ui.Dialogos
import com.vigia.core.ui.TipoBoton
import com.vigia.core.ui.Vistas
import com.vigia.core.util.Formato
import com.vigia.faro.adb.GestorAdb
import com.vigia.faro.forense.Evidencia
import com.vigia.faro.forense.Indicadores
import com.vigia.faro.forense.Libro
import com.vigia.faro.forense.Oui
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PrincipalActivity : ActividadBase() {

    private lateinit var textoRed: TextView
    private lateinit var botonCompleto: MaterialButton
    private lateinit var botonRouter: MaterialButton
    private lateinit var botonForense: MaterialButton
    private lateinit var cajaInternet: CheckBox
    private lateinit var textoAdb: TextView
    private lateinit var textoIoc: TextView
    private lateinit var botonCancelar: MaterialButton
    private lateinit var botonUbicacion: MaterialButton
    private lateinit var textoProgreso: TextView
    private lateinit var resultados: LinearLayout

    private var trabajo: Job? = null
    private var ultimo: ResultadoAnalisis? = null

    private val pedirUbicacion = registerForActivityResult(ActivityResultContracts.RequestPermission()) { mostrarRed() }

    private val abrirIoc = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) importarIoc(uri) }

    private val abrirEvidencia = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) verificarArchivo(uri) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        construirUi()
    }

    override fun onResume() {
        super.onResume()
        mostrarRed()
        mostrarModoForense()
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

        val forense = Vistas.tarjeta(this)
        forense.addView(Vistas.subtitulo(this, "Modo forense"), Vistas.anchoCompleto(this, 6))
        forense.addView(
            Vistas.texto(
                this,
                "Revisa también el propio teléfono (apps con accesos especiales, certificados, ajustes), compara la red con tu última visita y firma el informe como evidencia. " +
                    "Con el modo avanzado (ADB) añade la tabla ARP con MAC y fabricante, el Wi-Fi sin ubicación, las conexiones del teléfono y la detección de gemelos malvados.",
                true
            ),
            Vistas.anchoCompleto(this, 8)
        )
        textoAdb = Vistas.texto(this, "")
        forense.addView(textoAdb, Vistas.anchoCompleto(this, 6))
        forense.addView(Vistas.boton(this, "Modo avanzado (ADB)", TipoBoton.TONAL) { startActivity(Intent(this, AdbActivity::class.java)) }, Vistas.anchoCompleto(this, 8))
        cajaInternet = CheckBox(this)
        cajaInternet.text = "Incluir pruebas con internet (DNS, certificados HTTPS y ruta). Contactan con google.com, wikipedia.org, cloudflare.com, github.com y los DNS 1.1.1.1 y 8.8.8.8."
        cajaInternet.isChecked = true
        cajaInternet.setTextColor(Vistas.color(this, R.color.vc_texto_sec))
        cajaInternet.textSize = 12f
        forense.addView(cajaInternet, Vistas.anchoCompleto(this, 8))
        textoIoc = Vistas.texto(this, "", true)
        forense.addView(textoIoc, Vistas.anchoCompleto(this, 6))
        forense.addView(Vistas.boton(this, "Importar indicadores de compromiso (IOC)", TipoBoton.TONAL) { abrirIoc.launch(arrayOf("*/*")) }, Vistas.anchoCompleto(this, 6))
        forense.addView(Vistas.boton(this, "Quitar indicadores", TipoBoton.TONAL) { quitarIoc() }, Vistas.anchoCompleto(this, 6))
        forense.addView(Vistas.boton(this, "Historial de análisis", TipoBoton.TONAL) { mostrarHistorial() }, Vistas.anchoCompleto(this, 6))
        forense.addView(Vistas.boton(this, "Verificar un paquete de evidencia", TipoBoton.TONAL) { abrirEvidencia.launch(arrayOf("*/*")) }, Vistas.anchoCompleto(this, 0))
        raiz.addView(forense, Vistas.anchoCompleto(this, 12))

        botonForense = Vistas.boton(this, "Análisis forense total (tu red y tu teléfono)") { iniciar(Opciones(true, true, cajaInternet.isChecked)) }
        raiz.addView(botonForense, Vistas.anchoCompleto(this, 6))
        botonCompleto = Vistas.boton(this, "Análisis completo (router y dispositivos)", TipoBoton.TONAL) { iniciar(Opciones(true, false, cajaInternet.isChecked)) }
        raiz.addView(botonCompleto, Vistas.anchoCompleto(this, 6))
        botonRouter = Vistas.boton(this, "Solo router y red", TipoBoton.TONAL) { iniciar(Opciones(false, false, cajaInternet.isChecked)) }
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
        botonForense.isEnabled = puede
    }

    private fun mostrarModoForense() {
        val l = Indicadores.cargar(this)
        textoIoc.text = if (l == null) "Indicadores de compromiso: ninguno cargado. El Faro no trae listas propias: importa las tuyas (STIX2 o texto)."
        else "Indicadores cargados: " + l.valores.size + " (" + l.origen + ", " + Formato.fecha(l.importada) + ")"
        if (!GestorAdb.disponible()) {
            textoAdb.text = "Modo avanzado: no disponible (necesita Android 11 o superior)."
            return
        }
        textoAdb.text = if (GestorAdb.conectado) "Modo avanzado: conectado." else "Modo avanzado: sin conectar (el análisis forense funciona, con menos detalle)."
        lifecycleScope.launch {
            if (GestorAdb.conectado) {
                val vivo = GestorAdb.verificar()
                textoAdb.text = if (vivo) "Modo avanzado: conectado." else "Modo avanzado: la conexión se perdió. Vuelve a conectar."
            }
        }
    }

    private fun iniciar(op: Opciones) {
        val r = LectorRed.leer(this)
        if (!r.esWifi || r.gateway == null || r.ipLocal == null) {
            Dialogos.informar(this, "Sin Wi-Fi", "Conéctate a una red Wi-Fi para analizarla.")
            return
        }
        val publica = r.seguridad == Seguridad.ABIERTA || r.portalMarcado
        if (op.completo && publica) {
            Dialogos.confirmar(
                this, "Red pública",
                "Estás en una red abierta o con portal cautivo. Buscar y analizar los dispositivos de otras personas puede no estar permitido. " +
                    "Usa el análisis completo solo en TU red. ¿Continuar de todos modos?",
                "Continuar"
            ) { confirmarForense(r, op) }
        } else {
            confirmarForense(r, op)
        }
    }

    private fun confirmarForense(r: InfoRed, op: Opciones) {
        if (!op.forense) {
            lanzar(r, op)
            return
        }
        Dialogos.confirmar(
            this, "Análisis forense",
            "Se leerá información de ESTE teléfono (apps instaladas y sus accesos, ajustes de red y seguridad, certificados) y, si el modo avanzado está conectado, " +
                "datos del sistema por ADB (solo lectura). Nada de eso sale del teléfono: el informe lo compartes tú. " +
                (if (op.internet) "Las pruebas con internet contactan con servidores públicos. " else "") +
                "¿Continuar?",
            "Analizar"
        ) { lanzar(r, op) }
    }

    private fun lanzar(red: InfoRed, op: Opciones) {
        trabajo?.cancel()
        resultados.removeAllViews()
        botonCompleto.isEnabled = false
        botonRouter.isEnabled = false
        botonForense.isEnabled = false
        botonCancelar.visibility = View.VISIBLE
        trabajo = lifecycleScope.launch {
            try {
                val res = Orquestador.analizar(this@PrincipalActivity, red, op) { texto ->
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

        val f = res.forense
        if (f != null) {
            for (sec in f.secciones) {
                resultados.addView(Vistas.subtitulo(this, sec.titulo), Vistas.anchoCompleto(this, 6))
                val tarj = Vistas.tarjeta(this)
                val txt = Vistas.texto(this, sec.lineas.joinToString("\n"), true)
                txt.textSize = 12f
                txt.setTextIsSelectable(true)
                tarj.addView(txt)
                resultados.addView(tarj, Vistas.anchoCompleto(this, 8))
            }
            if (f.limitaciones.isNotEmpty()) {
                resultados.addView(Vistas.subtitulo(this, "Lo que no se pudo comprobar"), Vistas.anchoCompleto(this, 6))
                val tarj = Vistas.tarjeta(this)
                tarj.addView(Vistas.texto(this, f.limitaciones.joinToString("\n") { "• " + it }, true))
                resultados.addView(tarj, Vistas.anchoCompleto(this, 8))
            }
        }

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

        resultados.addView(Vistas.boton(this, "Compartir informe (texto)", TipoBoton.TONAL) { compartir(res) }, Vistas.anchoCompleto(this, 6))
        if (res.evidencia.isNotEmpty()) {
            resultados.addView(Vistas.boton(this, "Exportar evidencia firmada") { exportarEvidencia(res) }, Vistas.anchoCompleto(this, 6))
            resultados.addView(
                Vistas.texto(this, "Huella de la evidencia (SHA-256): " + res.huellaEvidencia.take(32) + "…", true),
                Vistas.anchoCompleto(this, 0)
            )
        }
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
        if (d.fabricante != null) sub.append(" · ").append(d.fabricante)
        if (d.macAleatoria) sub.append(" · MAC aleatoria")
        t.addView(Vistas.texto(this, sub.toString(), true))
        if (d.certificado != null) {
            val ct = Vistas.texto(this, "🔒 " + d.certificado, true)
            ct.textSize = 12f
            t.addView(ct)
        }
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
        if (d.mac != null) sb.append("MAC: ").append(d.mac).append(if (d.macAleatoria) " (aleatoria: el equipo oculta su MAC real)" else "").append('\n')
        if (d.certificado != null) sb.append("Certificado HTTPS: ").append(d.certificado).append('\n')
        if (d.fabricante != null) sb.append("Fabricante: ").append(d.fabricante).append('\n')
        if (d.modelo != null) sb.append("Modelo: ").append(d.modelo).append('\n')
        if (d.servicios.isNotEmpty()) sb.append("\nServicios anunciados:\n").append(d.servicios.joinToString("\n") { "· " + it }).append('\n')
        if (d.puertos.isNotEmpty()) {
            sb.append("\nPuertos abiertos:\n")
            for (p in d.puertos) sb.append("· ").append(p.def.puerto).append(' ').append(p.def.servicio).append(": ").append(p.def.nota).append('\n')
        }
        if (d.mac == null) sb.append("\nSin dirección MAC: Android 10+ no la deja leer a las apps. Conecta el modo avanzado (ADB) para verla.")
        else if (Oui.buscar(d.mac) != null) sb.append("\nEl fabricante se deduce del prefijo de la MAC (orientativo).")
        Dialogos.informar(this, d.nombreVisible, sb.toString())
    }

    private fun compartir(res: ResultadoAnalisis) {
        val texto = Analisis.textoCompleto(res)
        val i = Intent(Intent.ACTION_SEND)
        i.type = "text/plain"
        i.putExtra(Intent.EXTRA_SUBJECT, "Informe de seguridad de red · El Faro")
        i.putExtra(Intent.EXTRA_TEXT, texto)
        startActivity(Intent.createChooser(i, "Compartir informe"))
    }

    // ------------------------------------------------------------------ forense: evidencia, indicadores, historial

    private fun exportarEvidencia(res: ResultadoAnalisis) {
        Dialogos.confirmar(
            this, "Exportar evidencia firmada",
            "El paquete incluye datos de tu red y de tu teléfono: IP, MAC, nombres de equipos y apps y las salidas de cada comprobación. " +
                "Está firmado para que nadie pueda cambiarlo sin que se note, pero NO está cifrado. Compártelo solo con quien deba verlo.",
            "Exportar"
        ) {
            lifecycleScope.launch {
                try {
                    val uri = withContext(Dispatchers.IO) { Evidencia.exportar(this@PrincipalActivity, res) }
                    val i = Intent(Intent.ACTION_SEND)
                    i.type = "application/json"
                    i.putExtra(Intent.EXTRA_STREAM, uri)
                    i.putExtra(Intent.EXTRA_SUBJECT, "Evidencia firmada · El Faro")
                    i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    startActivity(Intent.createChooser(i, "Exportar evidencia"))
                } catch (e: Exception) {
                    Dialogos.informar(this@PrincipalActivity, "No se pudo exportar", e.message ?: e.javaClass.simpleName)
                }
            }
        }
    }

    private fun leerTexto(uri: Uri, max: Int): String? {
        return try {
            contentResolver.openInputStream(uri)?.use { ent ->
                val salida = java.io.ByteArrayOutputStream()
                val buf = ByteArray(8192)
                while (salida.size() <= max) {
                    val n = ent.read(buf)
                    if (n < 0) break
                    salida.write(buf, 0, n)
                }
                if (salida.size() > max) null else salida.toString("UTF-8")
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun verificarArchivo(uri: Uri) {
        lifecycleScope.launch {
            val texto = withContext(Dispatchers.IO) { leerTexto(uri, 30_000_000) }
            if (texto == null) {
                Dialogos.informar(this@PrincipalActivity, "No se pudo leer", "El archivo no se pudo abrir o es demasiado grande.")
                return@launch
            }
            val v = withContext(Dispatchers.IO) { Evidencia.verificar(this@PrincipalActivity, texto) }
            Dialogos.informar(this@PrincipalActivity, if (v.firmaValida) "Evidencia verificada" else "Evidencia NO verificada", v.texto)
        }
    }

    private fun importarIoc(uri: Uri) {
        lifecycleScope.launch {
            val n = withContext(Dispatchers.IO) {
                val texto = leerTexto(uri, 15_000_000)
                if (texto == null) -1 else Indicadores.importar(this@PrincipalActivity, texto, uri.lastPathSegment ?: "archivo")
            }
            when {
                n < 0 -> Dialogos.informar(this@PrincipalActivity, "No se pudo leer", "El archivo no se pudo abrir o es demasiado grande.")
                n == 0 -> Dialogos.informar(this@PrincipalActivity, "Sin indicadores", "No se encontró ninguna IP, dominio ni nombre de paquete válidos. Se admite STIX2 o un indicador por línea.")
                else -> Toast.makeText(this@PrincipalActivity, "Se importaron " + n + " indicadores.", Toast.LENGTH_LONG).show()
            }
            mostrarModoForense()
        }
    }

    private fun quitarIoc() {
        if (Indicadores.cargar(this) == null) {
            Toast.makeText(this, "No hay indicadores cargados.", Toast.LENGTH_SHORT).show()
            return
        }
        Dialogos.confirmar(this, "Quitar indicadores", "Se borrará la lista de indicadores de compromiso importada.", "Quitar") {
            Indicadores.borrar(this)
            mostrarModoForense()
        }
    }

    private fun mostrarHistorial() {
        val lista = Libro.cargar(this)
        if (lista.isEmpty()) {
            Dialogos.informar(this, "Historial", "Todavía no hay análisis forenses guardados. Cada «Análisis forense total» queda registrado aquí, encadenado con el anterior.")
            return
        }
        val rota = Libro.primeraRota(lista)
        val sb = StringBuilder()
        sb.append(if (rota == null) "Cadena íntegra.\n\n" else "CADENA ROTA a partir de la entrada n.º " + rota + ": el historial fue modificado.\n\n")
        for (e in lista.reversed().take(30)) {
            sb.append("n.º ").append(e.n).append(" · ").append(Formato.fecha(e.momento)).append('\n')
            sb.append("   ").append(e.red).append(" · ").append(e.puntuacion).append("/100 · ").append(e.hash.take(12)).append("…\n")
        }
        Dialogos.informar(this, "Historial de análisis", sb.toString())
    }
}
