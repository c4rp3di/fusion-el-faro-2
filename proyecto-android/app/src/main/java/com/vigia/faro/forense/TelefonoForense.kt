package com.vigia.faro.forense

import android.app.KeyguardManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import com.vigia.core.inventario.AppInfo
import com.vigia.faro.Riesgo
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Calendar

/** Revisión del propio teléfono que NO necesita ADB: bloqueo, proxy, certificados instalados y apps con accesos especiales. */
object TelefonoForense {

    private val GESTORES_ROOT = setOf(
        "com.topjohnwu.magisk", "eu.chainfire.supersu", "me.weishu.kernelsu", "com.koushikdutta.superuser",
        "com.noshufou.android.su", "com.thirdparty.superuser", "com.yellowes.su", "io.github.huskydg.magisk"
    )

    private val TIENDAS = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps", "com.amazon.venezia", "com.huawei.appmarket",
        "com.xiaomi.mipicks", "com.xiaomi.market", "org.fdroid.fdroid", "com.aurora.store", "com.heytap.market", "com.oppo.market"
    )

    fun analizar(c: Context, datos: DatosForenses, apps: List<AppInfo>, indicadores: Set<String>) {
        ajustes(c, datos)
        certificados(datos)
        aplicaciones(datos, apps, indicadores)
    }

    // ------------------------------------------------------------------ ajustes

    private fun mesesDesde(fecha: String): Int? {
        val partes = fecha.trim().split('-')
        if (partes.size < 2) return null
        val a = partes[0].toIntOrNull() ?: return null
        val me = partes[1].toIntOrNull() ?: return null
        val hoy = Calendar.getInstance()
        return (hoy.get(Calendar.YEAR) - a) * 12 + (hoy.get(Calendar.MONTH) + 1 - me)
    }

    private fun ajustes(c: Context, datos: DatosForenses) {
        val lineas = ArrayList<String>()
        lineas.add("Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ") · " + Build.MANUFACTURER + " " + Build.MODEL)
        val parche = if (Build.VERSION.SDK_INT >= 23) Build.VERSION.SECURITY_PATCH else null
        if (parche != null) {
            lineas.add("Parche de seguridad: " + parche)
            val meses = mesesDesde(parche)
            if (meses != null && meses >= 12) {
                datos.hallazgo(
                    Riesgo.MEDIO, "Parche de seguridad de hace " + meses + " meses",
                    "Faltan las correcciones de seguridad publicadas desde " + parche + ".",
                    "Busca actualizaciones del sistema. Si el fabricante ya no las da, usa el móvil con más cautela.", "Teléfono"
                )
            } else if (meses != null && meses >= 6) {
                datos.hallazgo(
                    Riesgo.BAJO, "Parche de seguridad de hace " + meses + " meses",
                    "Hay actualizaciones de seguridad posteriores a " + parche + ".",
                    "Comprueba si hay una actualización del sistema.", "Teléfono"
                )
            }
        }

        try {
            val kg = c.getSystemService(KeyguardManager::class.java)
            if (kg != null && !kg.isDeviceSecure) {
                datos.hallazgo(
                    Riesgo.MEDIO, "El teléfono no tiene bloqueo de pantalla",
                    "Cualquiera con acceso físico puede abrirlo, instalar software espía o leer tus datos.",
                    "Pon un PIN, patrón o huella en Ajustes > Seguridad.", "Teléfono"
                )
            }
            lineas.add("Bloqueo de pantalla: " + (if (kg != null && kg.isDeviceSecure) "sí" else "no"))
        } catch (e: Exception) {
        }

        try {
            val cr = c.contentResolver
            val usb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
            val dev = Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
            val wifiAdb = Settings.Global.getInt(cr, "adb_wifi_enabled", 0) == 1
            lineas.add("Opciones de desarrollador: " + (if (dev) "activadas" else "desactivadas") + " · depuración USB: " + (if (usb) "activada" else "desactivada") + " · inalámbrica: " + (if (wifiAdb) "activada" else "desactivada"))
            if (usb) {
                datos.hallazgo(
                    Riesgo.BAJO, "Depuración USB activada",
                    "Con el teléfono desbloqueado, un cable (o un equipo ya autorizado) puede controlarlo por ADB.",
                    "Desactívala en Opciones de desarrollador si no la necesitas.", "Teléfono"
                )
            }
        } catch (e: Exception) {
        }

        try {
            val cm = c.getSystemService(ConnectivityManager::class.java)
            val proxy = cm.defaultProxy
            if (proxy != null && !proxy.host.isNullOrEmpty()) {
                datos.hallazgo(
                    Riesgo.ALTO, "Proxy configurado (" + proxy.host + ":" + proxy.port + ")",
                    "El tráfico HTTP del teléfono pasa por ese equipo, que puede verlo y alterarlo.",
                    "Si no lo pusiste tú, quítalo (Ajustes > Wi-Fi > tu red > Proxy) y averigua qué lo configuró.", "Teléfono"
                )
                lineas.add("Proxy: " + proxy.host + ":" + proxy.port)
            } else {
                lineas.add("Proxy: ninguno")
            }
            val red = cm.activeNetwork
            val caps = if (red != null) cm.getNetworkCapabilities(red) else null
            val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            lineas.add("VPN activa: " + (if (vpn) "sí" else "no"))
            if (Build.VERSION.SDK_INT >= 28 && red != null) {
                val lp = cm.getLinkProperties(red)
                if (lp != null) {
                    val activo = lp.isPrivateDnsActive
                    lineas.add("DNS privado: " + (if (activo) "activo" + (if (lp.privateDnsServerName != null) " (" + lp.privateDnsServerName + ")" else "") else "inactivo"))
                    if (!activo) {
                        datos.hallazgo(
                            Riesgo.BAJO, "DNS privado inactivo",
                            "Las consultas DNS viajan sin cifrar: la red puede verlas o falsearlas.",
                            "Actívalo en Ajustes > Red > DNS privado (por ejemplo dns.google o one.one.one.one).", "Teléfono"
                        )
                    }
                }
            }
        } catch (e: Exception) {
        }
        datos.seccion("Teléfono", lineas)
    }

    // ------------------------------------------------------------------ certificados instalados por el usuario

    private fun usuarioCas(): List<X509Certificate> {
        val res = ArrayList<X509Certificate>()
        try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            for (alias in ks.aliases().toList()) {
                if (!alias.startsWith("user:")) continue
                val cert = ks.getCertificate(alias)
                if (cert is X509Certificate) res.add(cert)
            }
        } catch (e: Exception) {
        }
        return res
    }

    class CaUsuario(val huellas: Set<String>, val sujetos: Set<String>)

    /** Huellas y nombres de las CA instaladas por el usuario (la sonda TLS los usa para saber si una conexión pasa por una de ellas). */
    fun infoCaUsuario(): CaUsuario {
        val huellas = HashSet<String>()
        val sujetos = HashSet<String>()
        for (cert in usuarioCas()) {
            try {
                huellas.add(Huellas.sha256(cert.encoded))
                sujetos.add(cert.subjectX500Principal.name)
            } catch (e: Exception) {
            }
        }
        return CaUsuario(huellas, sujetos)
    }

    private fun certificados(datos: DatosForenses) {
        val lista = usuarioCas()
        if (lista.isEmpty()) return
        val nombres = lista.map { it.subjectX500Principal.name.take(70) }
        datos.hallazgo(
            Riesgo.MEDIO, lista.size.toString() + " certificado(s) de CA instalado(s) por el usuario",
            "Una autoridad instalada a mano permite a quien la controle descifrar el tráfico HTTPS de las apps y navegadores que la aceptan. Es normal con proxies de empresa o herramientas de depuración, y es una técnica típica de vigilancia: " + nombres.joinToString("; "),
            "Si no la instalaste tú, quítala en Ajustes > Seguridad > Cifrado y credenciales > Credenciales de confianza > Usuario.", "Teléfono"
        )
        datos.seccion("Certificados de CA instalados por el usuario", nombres)
    }

    // ------------------------------------------------------------------ apps

    private fun aplicaciones(datos: DatosForenses, apps: List<AppInfo>, indicadores: Set<String>) {
        if (apps.isEmpty()) {
            datos.limitaciones.add("No se pudo leer la lista de apps instaladas.")
            return
        }
        val terceros = apps.filter { !it.sistema }
        val lineas = ArrayList<String>()
        lineas.add(apps.size.toString() + " apps (" + terceros.size + " instaladas por ti o por terceros)")

        val root = apps.filter { GESTORES_ROOT.contains(it.paquete) }
        for (a in root) {
            datos.hallazgo(
                Riesgo.ALTO, "Gestor de root instalado: " + a.etiqueta,
                "Con root, las apps autorizadas pueden leer y modificar todo el sistema.",
                "Si no rooteaste tú el teléfono, restáuralo de fábrica con el sistema oficial.", "Teléfono"
            )
        }

        fun nombres(l: List<AppInfo>): String = l.take(6).joinToString(", ") { it.etiqueta } + (if (l.size > 6) "…" else "")

        val accesibilidad = terceros.filter { it.accesibilidad }
        if (accesibilidad.isNotEmpty()) {
            datos.hallazgo(
                Riesgo.MEDIO, accesibilidad.size.toString() + " app(s) con servicio de accesibilidad activo",
                "Un servicio de accesibilidad puede leer la pantalla y pulsar por ti. Lo usan gestores de contraseñas y ayudas legítimas, y también el software espía y los troyanos bancarios: " + nombres(accesibilidad) + ".",
                "Desactiva en Ajustes > Accesibilidad los que no reconozcas o no necesites.", "Teléfono"
            )
        }
        val admins = terceros.filter { it.administrador }
        if (admins.isNotEmpty()) {
            datos.hallazgo(
                Riesgo.MEDIO, admins.size.toString() + " app(s) administradora(s) del dispositivo",
                "Pueden bloquear o borrar el teléfono y dificultan desinstalarlas: " + nombres(admins) + ".",
                "Quita el permiso en Ajustes > Seguridad > Apps de administración del dispositivo si no las reconoces.", "Teléfono"
            )
        }
        val escuchas = terceros.filter { it.lectorNotificaciones }
        if (escuchas.isNotEmpty()) {
            datos.hallazgo(
                Riesgo.BAJO, escuchas.size.toString() + " app(s) leen tus notificaciones",
                "Ven el contenido de mensajes y códigos de verificación: " + nombres(escuchas) + ".",
                "Revisa Ajustes > Notificaciones > Acceso a notificaciones y quita las que no necesites.", "Teléfono"
            )
        }
        val teclados = terceros.filter { it.teclado }
        if (teclados.isNotEmpty()) {
            datos.hallazgo(
                Riesgo.BAJO, "Teclado de terceros activo: " + nombres(teclados),
                "Un teclado ve todo lo que escribes, incluidas contraseñas.",
                "Usa solo teclados de fabricantes de confianza.", "Teléfono"
            )
        }
        val fuera = terceros.filter { !TIENDAS.contains(it.instalador) }
        if (fuera.isNotEmpty()) {
            lineas.add(fuera.size.toString() + " app(s) instaladas fuera de una tienda conocida")
            datos.hallazgo(
                Riesgo.BAJO, fuera.size.toString() + " app(s) instaladas fuera de una tienda",
                "Instaladas desde un archivo APK o por ADB, sin la revisión de una tienda: " + nombres(fuera) + ".",
                "Comprueba que las instalaste tú. Desinstala las que no reconozcas.", "Teléfono"
            )
        }
        val revisar = terceros.filter { it.nivel == "revisar" }
        if (revisar.isNotEmpty()) {
            val detalle = revisar.take(5).joinToString("; ") { it.etiqueta + (if (it.motivos.isNotEmpty()) " (" + it.motivos.take(2).joinToString(", ") + ")" else "") }
            datos.hallazgo(
                Riesgo.BAJO, revisar.size.toString() + " app(s) con perfil de riesgo alto",
                "Por la combinación de permisos y accesos: " + detalle + ".",
                "Revisa qué permisos tiene cada una (Ajustes > Apps) y quita los innecesarios.", "Teléfono"
            )
        }
        if (indicadores.isNotEmpty()) {
            for (a in apps) {
                if (indicadores.contains(a.paquete.lowercase())) {
                    datos.hallazgo(
                        Riesgo.CRITICO, "App que figura en tus indicadores de compromiso: " + a.etiqueta,
                        "El paquete " + a.paquete + " coincide con la lista de indicadores que importaste.",
                        "Desinstálala, cambia tus contraseñas desde otro dispositivo y conserva la evidencia firmada.", "IOC"
                    )
                }
            }
        }
        datos.seccion("Apps", lineas)
    }
}
