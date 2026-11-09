package com.vigia.faro

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.lifecycle.lifecycleScope
import com.vigia.core.R
import com.vigia.core.ui.ActividadBase
import com.vigia.core.ui.Dialogos
import com.vigia.core.ui.TipoBoton
import com.vigia.core.ui.Vistas
import com.vigia.faro.adb.GestorAdb
import kotlinx.coroutines.launch

/** Empareja y conecta el modo avanzado (depuración inalámbrica de este mismo teléfono) que usa el análisis forense. */
class AdbActivity : ActividadBase() {

    private lateinit var estado: TextView
    private lateinit var registro: TextView
    private lateinit var etPuerto: EditText
    private lateinit var etCodigo: EditText
    private lateinit var etPuertoCon: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        construirUi()
    }

    override fun onResume() {
        super.onResume()
        refrescar()
    }

    private fun campo(pista: String): EditText {
        val e = EditText(this)
        e.hint = pista
        e.setSingleLine(true)
        e.inputType = InputType.TYPE_CLASS_NUMBER
        e.setTextColor(Vistas.color(this, R.color.vc_texto))
        e.setHintTextColor(Vistas.color(this, R.color.vc_texto_sec))
        return e
    }

    private fun construirUi() {
        val raiz = Vistas.columna(this, 16)
        raiz.addView(Vistas.titulo(this, "Modo avanzado (ADB)"), Vistas.anchoCompleto(this, 2))
        raiz.addView(
            Vistas.texto(
                this,
                "Con la depuración inalámbrica de Android, El Faro puede LEER información que una app normal no ve: la tabla ARP (direcciones MAC), " +
                    "el Wi-Fi sin pedir ubicación, las conexiones de red del teléfono con la app que las abre y la administración del dispositivo. " +
                    "Solo lee: no cambia ajustes, no toca archivos personales y no envía nada fuera del teléfono. Necesita Android 11 o superior.",
                true
            ),
            Vistas.anchoCompleto(this, 12)
        )

        val tEstado = Vistas.tarjeta(this)
        estado = Vistas.texto(this, "Comprobando la conexión…")
        tEstado.addView(estado, Vistas.anchoCompleto(this, 4))
        registro = Vistas.texto(this, "", true)
        tEstado.addView(registro)
        raiz.addView(tEstado, Vistas.anchoCompleto(this, 12))

        val t1 = Vistas.tarjeta(this)
        t1.addView(Vistas.subtitulo(this, "1. Emparejar (una sola vez)"), Vistas.anchoCompleto(this, 6))
        t1.addView(
            Vistas.texto(
                this,
                "Conecta el móvil a una red Wi-Fi. En Opciones de desarrollador activa «Depuración inalámbrica», entra y pulsa «Vincular dispositivo con código de sincronización»: " +
                    "verás un código de 6 dígitos y una dirección con un puerto (los números tras los dos puntos). Escríbelos aquí. " +
                    "Usa la pantalla dividida o una ventana flotante para ver ambas pantallas a la vez: si sales de la de Android, el código caduca.",
                true
            ),
            Vistas.anchoCompleto(this, 8)
        )
        t1.addView(Vistas.boton(this, "Abrir opciones de desarrollador", TipoBoton.TONAL) { abrirDesarrollo() }, Vistas.anchoCompleto(this, 8))
        etPuerto = campo("Puerto de emparejamiento")
        t1.addView(etPuerto, Vistas.anchoCompleto(this, 4))
        etCodigo = campo("Código de 6 dígitos")
        t1.addView(etCodigo, Vistas.anchoCompleto(this, 8))
        t1.addView(Vistas.boton(this, "Emparejar") { emparejar() }, Vistas.anchoCompleto(this, 0))
        raiz.addView(t1, Vistas.anchoCompleto(this, 12))

        val t2 = Vistas.tarjeta(this)
        t2.addView(Vistas.subtitulo(this, "2. Conectar"), Vistas.anchoCompleto(this, 6))
        t2.addView(
            Vistas.texto(
                this,
                "Con la depuración inalámbrica activada, pulsa «Conectar»: El Faro intenta detectar solo el puerto de conexión. Si no lo consigue, escribe el que aparece en la pantalla principal de Depuración inalámbrica, " +
                    "junto a «Dirección IP y puerto» (es distinto del de emparejamiento). Tendrás que volver a conectar cada vez que reinicies el teléfono o cambies de red Wi-Fi.",
                true
            ),
            Vistas.anchoCompleto(this, 8)
        )
        etPuertoCon = campo("Puerto de conexión (opcional)")
        t2.addView(etPuertoCon, Vistas.anchoCompleto(this, 8))
        t2.addView(Vistas.boton(this, "Conectar") { conectar() }, Vistas.anchoCompleto(this, 0))
        raiz.addView(t2, Vistas.anchoCompleto(this, 12))

        val t3 = Vistas.tarjeta(this)
        t3.addView(Vistas.subtitulo(this, "3. Al terminar"), Vistas.anchoCompleto(this, 6))
        t3.addView(
            Vistas.texto(
                this,
                "Mientras la depuración inalámbrica siga activa, quien consiga emparejarse con un código podría controlar el teléfono. Desactívala en Opciones de desarrollador cuando termines. " +
                    "«Olvidar» borra las claves de emparejamiento de El Faro.",
                true
            ),
            Vistas.anchoCompleto(this, 8)
        )
        t3.addView(Vistas.boton(this, "Olvidar el emparejamiento", TipoBoton.PELIGRO) { olvidar() }, Vistas.anchoCompleto(this, 0))
        raiz.addView(t3, Vistas.anchoCompleto(this, 12))

        val scroll = ScrollView(this)
        scroll.addView(raiz)
        setContentView(scroll)
    }

    private fun refrescar() {
        if (!GestorAdb.disponible()) {
            estado.text = "El modo avanzado necesita Android 11 o superior. El análisis forense funciona sin él, con menos detalle."
            return
        }
        lifecycleScope.launch {
            val vivo = GestorAdb.conectado && GestorAdb.verificar()
            estado.text = if (vivo) "Conectado: El Faro puede leer el sistema." else "Sin conexión con el modo avanzado."
        }
    }

    private fun abrirDesarrollo() {
        try {
            startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
        } catch (e: Exception) {
            Toast.makeText(this, "No se pudo abrir las opciones de desarrollador.", Toast.LENGTH_LONG).show()
        }
    }

    private fun emparejar() {
        if (!GestorAdb.disponible()) {
            Toast.makeText(this, "Necesita Android 11 o superior.", Toast.LENGTH_LONG).show()
            return
        }
        val puerto = etPuerto.text.toString().trim().toIntOrNull()
        val codigo = etCodigo.text.toString().trim()
        if (puerto == null || puerto < 1 || puerto > 65535 || codigo.length != 6) {
            Toast.makeText(this, "Escribe el puerto (hasta 5 cifras) y el código de 6 dígitos que muestra Android.", Toast.LENGTH_LONG).show()
            return
        }
        estado.text = "Emparejando…"
        lifecycleScope.launch {
            val resultado = try {
                if (GestorAdb.emparejar(applicationContext, puerto, codigo)) "emparejado" else "rechazado"
            } catch (e: Exception) {
                "error: " + e.javaClass.simpleName + " " + (e.message ?: "")
            }
            registro.text = "Emparejar → " + resultado
            if (resultado == "emparejado") {
                etCodigo.setText("")
                estado.text = "Emparejado. Ahora pulsa «Conectar»."
            } else {
                estado.text = "No se pudo emparejar. Comprueba el puerto y el código, y que la pantalla de emparejamiento siga abierta (el código caduca al cerrarla)."
            }
        }
    }

    private fun conectar() {
        if (!GestorAdb.disponible()) {
            Toast.makeText(this, "Necesita Android 11 o superior.", Toast.LENGTH_LONG).show()
            return
        }
        val texto = etPuertoCon.text.toString().trim()
        val manual = if (texto.isEmpty()) null else texto.toIntOrNull()
        if (texto.isNotEmpty() && (manual == null || manual < 1 || manual > 65535)) {
            Toast.makeText(this, "El puerto no es válido.", Toast.LENGTH_LONG).show()
            return
        }
        estado.text = "Conectando…"
        lifecycleScope.launch {
            val resultado = try {
                if (GestorAdb.conectar(applicationContext, manual)) "conectado" else "sin conexión"
            } catch (e: Exception) {
                "error: " + e.javaClass.simpleName + " " + (e.message ?: "")
            }
            registro.text = "Conectar → " + resultado
            estado.text = if (resultado == "conectado") "Conectado: El Faro puede leer el sistema." else "No se pudo conectar. Comprueba que la depuración inalámbrica sigue activada y que estás en una red Wi-Fi."
        }
    }

    private fun olvidar() {
        Dialogos.confirmar(this, "Olvidar el emparejamiento", "Se borrarán las claves de ADB de El Faro. Para volver a usar el modo avanzado tendrás que emparejar otra vez.", "Olvidar") {
            GestorAdb.olvidar(this)
            registro.text = ""
            refrescar()
        }
    }
}
