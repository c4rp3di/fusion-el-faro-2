package com.vigia.faro

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.widget.Toast

/** Una acción que abre una pantalla del sistema (o el navegador) relacionada con un hallazgo. */
class AccionSistema(val etiqueta: String, val intent: Intent)

object Acciones {

    private val FUENTES_ROUTER = setOf("UPnP", "DNS", "DHCP", "Cambios", "Versiones", "Certificados", "Traza", "IPv6")

    /** Atajos a los ajustes de Android (y al panel del router) que ayudan a resolver un hallazgo. */
    fun paraHallazgo(h: Hallazgo, gateway: String?): List<AccionSistema> {
        val t = h.titulo.lowercase()
        val l = ArrayList<AccionSistema>()
        fun aj(etiqueta: String, accion: String) {
            l.add(AccionSistema(etiqueta, Intent(accion)))
        }
        fun contiene(vararg claves: String): Boolean = claves.any { t.contains(it) }

        if (contiene("accesibilidad")) aj("Abrir ajustes de accesibilidad", Settings.ACTION_ACCESSIBILITY_SETTINGS)
        if (contiene("notificaciones")) aj("Abrir acceso a notificaciones", Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
        if (contiene("administrador", "administrado", "bloqueo de pantalla", "certificado(s) de ca", "autoridad instalada", "autoridad de certificación")) {
            aj("Abrir ajustes de seguridad", Settings.ACTION_SECURITY_SETTINGS)
        }
        if (contiene("wi-fi", "red(es) abierta", "gemelo", "mismo nombre", "proxy", "cifrado wep")) aj("Abrir ajustes Wi-Fi", Settings.ACTION_WIFI_SETTINGS)
        if (contiene("dns privado")) aj("Abrir ajustes de red", Settings.ACTION_WIRELESS_SETTINGS)
        if (contiene("depuración", "adb", "desarrollador")) aj("Abrir opciones de desarrollador", Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
        if (contiene("app(s)", "apps", "apk", "gestor de root", "instaladas")) aj("Abrir la lista de apps", Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS)
        if (contiene("parche", "sistema compilado", "bootloader", "claves de prueba", "root")) aj("Abrir información del teléfono", Settings.ACTION_DEVICE_INFO_SETTINGS)
        if (contiene("bluetooth", "rastreador")) aj("Abrir ajustes de Bluetooth", Settings.ACTION_BLUETOOTH_SETTINGS)
        if (gateway != null && (FUENTES_ROUTER.contains(h.fuente) || contiene("router"))) {
            l.add(AccionSistema("Abrir el panel del router", Intent(Intent.ACTION_VIEW, Uri.parse("http://" + gateway))))
        }
        return l
    }

    fun lanzar(c: Context, a: AccionSistema) {
        try {
            c.startActivity(a.intent)
        } catch (e: Exception) {
            Toast.makeText(c, "No se pudo abrir esa pantalla en este teléfono.", Toast.LENGTH_LONG).show()
        }
    }

    fun abrirUrl(c: Context, url: String) {
        lanzar(c, AccionSistema("", Intent(Intent.ACTION_VIEW, Uri.parse(url))))
    }

    fun copiar(c: Context, texto: String) {
        try {
            val cm = c.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("El Faro", texto))
            Toast.makeText(c, "Copiado.", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(c, "No se pudo copiar.", Toast.LENGTH_SHORT).show()
        }
    }

    fun compartir(c: Context, asunto: String, texto: String) {
        val i = Intent(Intent.ACTION_SEND)
        i.type = "text/plain"
        i.putExtra(Intent.EXTRA_SUBJECT, asunto)
        i.putExtra(Intent.EXTRA_TEXT, texto)
        c.startActivity(Intent.createChooser(i, "Compartir"))
    }
}
