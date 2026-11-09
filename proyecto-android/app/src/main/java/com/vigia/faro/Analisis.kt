package com.vigia.faro

import com.vigia.core.red.UtilRed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class EstadoPortal { LIBRE, PORTAL, SIN_INTERNET, NO_COMPROBADO }

class ResultadoPortal(val estado: EstadoPortal, val detalle: String)

object Portal {
    /**
     * Pide una URL que debe contestar «204 sin contenido». Si un portal cautivo intercepta la conexión, responderá
     * con otra cosa (una página o una redirección). Es el mismo método que usa Android.
     */
    suspend fun comprobar(): ResultadoPortal = withContext(Dispatchers.IO) {
        try {
            val con = URL("http://connectivitycheck.gstatic.com/generate_204").openConnection() as HttpURLConnection
            con.connectTimeout = 4000
            con.readTimeout = 4000
            con.instanceFollowRedirects = false
            val codigo = con.responseCode
            con.disconnect()
            when {
                codigo == 204 -> ResultadoPortal(EstadoPortal.LIBRE, "Salida a internet directa.")
                codigo in 200..399 -> ResultadoPortal(EstadoPortal.PORTAL, "La red interceptó la conexión (código " + codigo + "): pide iniciar sesión.")
                else -> ResultadoPortal(EstadoPortal.SIN_INTERNET, "Respuesta inesperada (" + codigo + ").")
            }
        } catch (e: Exception) {
            ResultadoPortal(EstadoPortal.SIN_INTERNET, "No se pudo salir a internet desde esta red.")
        }
    }
}

class Hallazgo(val riesgo: Riesgo, val titulo: String, val detalle: String, val accion: String, val fuente: String = "")

class Informe(val puntuacion: Int, val veredicto: String, val hallazgos: List<Hallazgo>)

object Analisis {

    private val DNS_PUBLICOS = setOf(
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15"
    )

    private fun accionPuerto(p: Int): String {
        return when (p) {
            23, 2323 -> "Desactiva Telnet en la configuración. Si no puedes, actualiza el firmware o cambia de equipo."
            21 -> "Desactiva el servidor FTP o sustitúyelo por uno cifrado (SFTP)."
            80, 8000, 8080 -> "Usa la versión HTTPS del panel si existe y cambia la contraseña de fábrica."
            139, 445 -> "Desactiva la compartición de archivos si no la usas."
            554 -> "Ponle contraseña a la cámara y no la expongas a internet."
            5555 -> "Desactiva la depuración ADB por red (usa solo la de cable)."
            3389, 5900 -> "Desactívalo o protégelo con una contraseña fuerte y una VPN."
            1723 -> "Cambia a una VPN moderna (WireGuard u OpenVPN)."
            7547 -> "Mantén el firmware al día y pregunta al operador si puede restringirse."
            8291 -> "Actualiza RouterOS y limita Winbox a tu equipo de administración."
            37215 -> "Actualiza el firmware del router o sustitúyelo: ese puerto se ha explotado en ataques reales."
            9100 -> "Restringe la impresión a tu red local y a quien la necesite."
            else -> "Desactiva el servicio si no lo usas."
        }
    }

    private fun esAntiguo(banner: String?): Boolean {
        if (banner == null) return false
        val b = banner.lowercase()
        return b.contains("boa/") || b.contains("mini_httpd") || b.contains("goahead") || b.contains("dropbear_2012") || b.contains("micro_httpd")
    }

    fun evaluar(
        red: InfoRed,
        portal: ResultadoPortal,
        router: Dispositivo?,
        dispositivos: List<Dispositivo>,
        upnpRouter: Boolean,
        forenses: List<Hallazgo> = emptyList()
    ): Informe {
        val h = ArrayList<Hallazgo>()

        // ---- la red Wi-Fi
        when (red.seguridad) {
            Seguridad.ABIERTA -> h.add(
                Hallazgo(Riesgo.CRITICO, "Red Wi-Fi sin contraseña", "Cualquiera puede conectarse y lo que no vaya cifrado se puede espiar o alterar.", "Evita iniciar sesión o pagar en ella y usa una VPN. En tu propio router, activa WPA2 o WPA3.")
            )
            Seguridad.WEP -> h.add(
                Hallazgo(Riesgo.CRITICO, "Cifrado WEP", "WEP se rompe en minutos con herramientas públicas.", "Cambia el router a WPA2 o WPA3.")
            )
            Seguridad.WPA -> h.add(
                Hallazgo(Riesgo.ALTO, "Cifrado WPA antiguo", "WPA (TKIP) tiene debilidades conocidas.", "Pasa el router a WPA2-AES o WPA3.")
            )
            Seguridad.OWE -> h.add(
                Hallazgo(Riesgo.BAJO, "Red abierta con cifrado (OWE)", "El tráfico va cifrado, pero cualquiera puede unirse.", "Mejor una red con contraseña si es la tuya.")
            )
            Seguridad.WPA2 -> h.add(Hallazgo(Riesgo.INFO, "Cifrado WPA2 o similar", "Es un cifrado adecuado si la contraseña es larga.", "WPA3 sería aún mejor si tu router lo ofrece."))
            Seguridad.WPA3 -> h.add(Hallazgo(Riesgo.INFO, "Cifrado WPA3", "Es el estándar más seguro disponible.", "Nada que hacer."))
            Seguridad.EMPRESA -> h.add(Hallazgo(Riesgo.INFO, "Red empresarial (802.1X)", "Autenticación por usuario.", "Nada que hacer."))
            Seguridad.DESCONOCIDA -> h.add(
                Hallazgo(Riesgo.INFO, "No se pudo comprobar el cifrado", "Android oculta el tipo de seguridad si la app no tiene permiso de ubicación.", "Concede el permiso desde la pantalla principal para verlo.")
            )
        }

        if (portal.estado == EstadoPortal.PORTAL || red.portalMarcado) {
            h.add(
                Hallazgo(Riesgo.ALTO, "Red con portal cautivo", "Es típico de hoteles, cafeterías y aeropuertos: la comparten desconocidos y el operador de la red puede ver el tráfico no cifrado.", "No uses cuentas importantes sin VPN y desconfía de portales que piden más datos de los necesarios.")
            )
        } else if (portal.estado == EstadoPortal.SIN_INTERNET) {
            h.add(Hallazgo(Riesgo.INFO, "Sin salida a internet", portal.detalle, "Comprueba el router o el operador."))
        }

        for (d in red.dns) {
            val n = UtilRed.parseIpv4(d)
            val privada = n != null && UtilRed.esIpPrivada(n)
            if (!privada && !DNS_PUBLICOS.contains(d)) {
                h.add(Hallazgo(Riesgo.BAJO, "Servidor DNS poco habitual (" + d + ")", "No es el router ni un DNS público conocido. Suele ser el de tu operador, pero un DNS malicioso puede redirigirte a webs falsas.", "Si no lo reconoces, fija un DNS fiable (por ejemplo 1.1.1.1 o 9.9.9.9) en el router."))
            }
        }

        if (upnpRouter) {
            h.add(
                Hallazgo(Riesgo.MEDIO, "UPnP activo en el router", "Programas de la red pueden abrir puertos hacia internet sin que lo sepas.", "Desactiva UPnP en el router si no lo necesitas (consolas y algunas videollamadas lo usan).")
            )
        }

        // ---- el router
        if (router != null) {
            for (p in router.puertos) {
                val d = p.def
                if (d.puerto == 80 && p.redirigeAHttps) {
                    h.add(Hallazgo(Riesgo.INFO, "El panel del router redirige a HTTPS", "El acceso web se cifra.", "Nada que hacer."))
                    continue
                }
                if (d.riesgo.ordinal <= Riesgo.MEDIO.ordinal) {
                    val extra = if (esAntiguo(p.banner)) " El software parece antiguo (" + p.banner + ")." else if (p.banner != null) " Detectado: " + p.banner + "." else ""
                    val riesgo = if (esAntiguo(p.banner) && d.riesgo == Riesgo.MEDIO) Riesgo.ALTO else d.riesgo
                    h.add(Hallazgo(riesgo, "Router: " + d.servicio + " abierto (puerto " + d.puerto + ")", d.nota + extra, accionPuerto(d.puerto)))
                }
            }
        }

        // ---- el resto de equipos
        var mediosSinCifrar = 0
        var sinIdentificar = 0
        var nuevos = 0
        for (d in dispositivos) {
            if (d.esRouter) continue
            if (d.nuevo) nuevos++
            if (d.tipo == Tipo.DESCONOCIDO && !d.esEsteTelefono) sinIdentificar++
            val cuando = if (d.esEsteTelefono) "Este teléfono" else d.nombreVisible + " (" + d.ip + ")"
            for (p in d.puertos) {
                val def = p.def
                if (def.riesgo == Riesgo.CRITICO || def.riesgo == Riesgo.ALTO) {
                    h.add(Hallazgo(def.riesgo, cuando + ": " + def.servicio + " abierto", def.nota, accionPuerto(def.puerto)))
                } else if (def.riesgo == Riesgo.MEDIO) {
                    if (d.tipo == Tipo.CAMARA && (def.puerto == 554 || def.puerto == 80)) {
                        h.add(Hallazgo(Riesgo.MEDIO, cuando + ": cámara con " + def.servicio + " sin cifrar", def.nota, accionPuerto(def.puerto)))
                    } else {
                        mediosSinCifrar++
                    }
                }
            }
        }
        if (mediosSinCifrar > 0) {
            h.add(Hallazgo(Riesgo.BAJO, mediosSinCifrar.toString() + " servicios sin cifrar en otros equipos", "Paneles web, archivos compartidos o impresión sin cifrar. Es habitual en redes domésticas.", "Revisa en cada dispositivo si de verdad necesita esos servicios."))
        }
        if (nuevos > 0) {
            h.add(Hallazgo(Riesgo.MEDIO, nuevos.toString() + " dispositivo(s) nuevo(s) desde la última vez", "Han aparecido equipos que no estaban en el análisis anterior de esta red.", "Compruébalos en la lista. Si no los reconoces, cambia la contraseña del Wi-Fi."))
        }
        if (sinIdentificar >= 3) {
            h.add(Hallazgo(Riesgo.INFO, sinIdentificar.toString() + " dispositivos sin identificar", "No respondieron con un nombre ni con servicios reconocibles.", "Comprueba que sabes qué son (televisores, bombillas, enchufes inteligentes…)."))
        }

        h.addAll(forenses)

        var puntos = 100
        for (x in h) puntos -= x.riesgo.peso
        puntos = puntos.coerceIn(0, 100)
        val veredicto = if (puntos >= 85) "Buena" else if (puntos >= 65) "Aceptable" else if (puntos >= 40) "Mejorable" else "Peligrosa"
        val orden = h.sortedBy { it.riesgo.ordinal }
        return Informe(puntos, veredicto, orden)
    }

    /** Informe en texto plano para compartir. */
    fun texto(red: InfoRed, informe: Informe, router: Dispositivo?, dispositivos: List<Dispositivo>): String {
        val sb = StringBuilder()
        val fecha = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date())
        sb.append("EL FARO · informe de seguridad de red\n").append(fecha).append("\n\n")
        sb.append("Red: ").append(red.ssid ?: "(oculta)").append(" · ").append(red.seguridad.etiqueta).append('\n')
        sb.append("IP del teléfono: ").append(red.ipLocal ?: "?").append(" · router: ").append(red.gateway ?: "?").append('\n')
        sb.append("DNS: ").append(if (red.dns.isEmpty()) "?" else red.dns.joinToString(", ")).append("\n\n")
        sb.append("Puntuación: ").append(informe.puntuacion).append("/100 (").append(informe.veredicto).append(") — orientativa\n\n")
        sb.append("HALLAZGOS\n")
        for (h in informe.hallazgos) {
            sb.append("[").append(h.riesgo.etiqueta.uppercase()).append("] ").append(h.titulo).append('\n')
            sb.append("  ").append(h.detalle).append('\n')
            if (h.riesgo != Riesgo.INFO) sb.append("  Qué hacer: ").append(h.accion).append('\n')
        }
        if (router != null) {
            sb.append("\nROUTER ").append(router.ip).append('\n')
            if (router.puertos.isEmpty()) sb.append("  Ningún puerto del catálogo abierto.\n")
            for (p in router.puertos) sb.append("  ").append(p.def.puerto).append(' ').append(p.def.servicio).append(if (p.banner != null) " — " + p.banner else "").append('\n')
        }
        if (dispositivos.isNotEmpty()) {
            sb.append("\nDISPOSITIVOS (").append(dispositivos.size).append(")\n")
            for (d in dispositivos) {
                sb.append("  ").append(d.ip).append("  ").append(d.nombreVisible).append(" · ").append(d.tipo.etiqueta)
                if (d.puertos.isNotEmpty()) sb.append(" · puertos ").append(d.puertos.joinToString(",") { it.def.puerto.toString() })
                sb.append('\n')
            }
        }
        sb.append("\nGenerado por El Faro. Es una guía orientativa, no una auditoría.\n")
        return sb.toString()
    }

    /** Informe en texto plano con todo lo que averiguó el análisis forense. */
    fun textoCompleto(res: ResultadoAnalisis): String {
        val sb = StringBuilder(texto(res.red, res.informe, res.router, res.dispositivos.filter { !it.esRouter }))
        val f = res.forense ?: return sb.toString()
        for (s in f.secciones) {
            sb.append('\n').append(s.titulo.uppercase()).append('\n')
            for (l in s.lineas) sb.append("  ").append(l).append('\n')
        }
        if (f.limitaciones.isNotEmpty()) {
            sb.append("\nNO SE PUDO COMPROBAR\n")
            for (l in f.limitaciones) sb.append("  ").append(l).append('\n')
        }
        if (res.huellaEvidencia.isNotEmpty()) sb.append("\nHuella de la evidencia (SHA-256): ").append(res.huellaEvidencia).append('\n')
        return sb.toString()
    }
}
