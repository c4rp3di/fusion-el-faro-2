package com.vigia.faro.forense

import android.content.Context
import com.vigia.core.inventario.AppInfo
import com.vigia.core.red.UtilRed
import com.vigia.faro.InfoRed
import com.vigia.faro.Riesgo
import java.util.Locale

/** Convierte lo que devolvió ADB en hallazgos y secciones del informe. Cada comprobación es independiente: si una falla, las demás siguen. */
object AnalisisAdb {

    /** IP → MAC de la tabla de vecinos (solo IPv4 y solo entradas con MAC conocida). */
    fun tablaIpv4(m: Map<String, String>): Map<String, String> {
        val res = HashMap<String, String>()
        for (v in ParserShell.vecinos(m["vecinos"] ?: "")) {
            if (v.mac != null && v.ip.contains('.') && v.estado != "FAILED" && v.estado != "INCOMPLETE") res[v.ip] = v.mac
        }
        return res
    }

    private fun esLocalOEspecial(ip: String): Boolean {
        val n = UtilRed.parseIpv4(ip)
        if (n != null) return UtilRed.esIpPrivada(n) || ip == "0.0.0.0" || ((n ushr 24) and 0xFF) >= 224
        val l = ip.lowercase()
        return l == "::" || l == "::1" || l.startsWith("fe80") || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("ff")
    }

    private fun esLoopback(ip: String): Boolean {
        val n = UtilRed.parseIpv4(ip)
        return if (n != null) ((n ushr 24) and 0xFF) == 127 else ip == "::1"
    }

    private fun etiquetaTipoSeguridad(t: Int): String {
        return when (t) {
            0 -> "Abierta"
            1 -> "WEP"
            2 -> "WPA/WPA2 con contraseña"
            3, 5, 9, 10 -> "Empresarial (802.1X)"
            4 -> "WPA3"
            6 -> "OWE (abierta con cifrado)"
            7, 8 -> "WAPI"
            else -> "tipo " + t
        }
    }

    private fun estandarWifi(e: Int): String {
        return when (e) {
            4 -> "Wi-Fi 4 (n)"
            5 -> "Wi-Fi 5 (ac)"
            6 -> "Wi-Fi 6 (ax)"
            7 -> "802.11ad"
            8 -> "Wi-Fi 7 (be)"
            else -> "estándar anterior"
        }
    }

    private fun hace(ms: Long): String {
        val min = ms / 60_000L
        return if (min < 60) min.toString() + " min" else if (min < 48 * 60) (min / 60).toString() + " h" else (min / 1440).toString() + " días"
    }

    fun analizar(
        c: Context,
        datos: DatosForenses,
        m: Map<String, String>,
        red: InfoRed,
        apps: List<AppInfo>,
        indicadores: Set<String>
    ) {
        sistema(datos, m)
        ajustes(datos, m)
        propietarios(datos, m, apps)
        wifi(datos, m, red)
        vecinos(datos, m, red)
        conexiones(c, datos, m, apps, indicadores)
        appsProfundo(datos, m, apps)
        archivos(datos, m)
    }

    // ------------------------------------------------------------------ propiedades y ajustes

    private fun sistema(datos: DatosForenses, m: Map<String, String>) {
        val p = ParserShell.propiedades(m["props"] ?: "")
        if (p.isEmpty()) {
            datos.limitaciones.add("ADB no devolvió las propiedades del sistema (getprop).")
            return
        }
        val lineas = ArrayList<String>()
        lineas.add("Modelo: " + (p["ro.product.manufacturer"] ?: "?") + " " + (p["ro.product.model"] ?: "?"))
        lineas.add("Android " + (p["ro.build.version.release"] ?: "?") + " · parche de seguridad " + (p["ro.build.version.security_patch"] ?: "?"))
        if (p["ro.build.fingerprint"] != null) lineas.add("Huella del sistema: " + p["ro.build.fingerprint"])
        val kernel = (m["kernel"] ?: "").lines().firstOrNull()?.trim()
        if (!kernel.isNullOrEmpty()) lineas.add("Kernel: " + kernel)
        val shell = (m["identidad"] ?: "").lines().firstOrNull()?.trim()
        if (!shell.isNullOrEmpty()) lineas.add("Sesión ADB: " + shell)
        datos.seccion("Sistema (ADB)", lineas)

        if (p["ro.debuggable"] == "1") {
            datos.hallazgo(
                Riesgo.ALTO, "Sistema compilado para depuración",
                "ro.debuggable=1: es una compilación de pruebas que da más poder a quien se conecte por ADB.",
                "Si no es un móvil de desarrollo, instala el sistema oficial del fabricante.", "ADB"
            )
        }
        if ((p["ro.build.tags"] ?: "").contains("test-keys")) {
            datos.hallazgo(
                Riesgo.MEDIO, "Sistema firmado con claves de prueba",
                "Suele indicar una ROM personalizada (no es el sistema oficial del fabricante).",
                "Comprueba que instalaste esa ROM tú y de una fuente fiable.", "ADB"
            )
        }
        val arranque = p["ro.boot.verifiedbootstate"]
        val bloqueado = p["ro.boot.flash.locked"]
        val vbmeta = p["ro.boot.vbmeta.device_state"]
        if (arranque == "orange" || bloqueado == "0" || vbmeta == "unlocked") {
            datos.hallazgo(
                Riesgo.ALTO, "Bootloader desbloqueado",
                "El arranque verificado está desactivado: el sistema podría haberse modificado sin que Android lo detecte.",
                "Si no lo desbloqueaste tú, revisa el teléfono con cuidado. Vuelve a bloquearlo si es posible.", "ADB"
            )
        } else if (arranque == "yellow" || arranque == "red") {
            datos.hallazgo(
                Riesgo.MEDIO, "Arranque verificado con aviso (" + arranque + ")",
                "El sistema usa una clave que no es la del fabricante o falló la verificación.",
                "Comprueba el origen del sistema instalado.", "ADB"
            )
        }
        val puertoTcp = listOf(p["service.adb.tcp.port"], p["persist.adb.tcp.port"]).firstOrNull { it != null && it.isNotEmpty() && it != "-1" && it != "0" }
        if (puertoTcp != null) {
            datos.hallazgo(
                Riesgo.CRITICO, "ADB por red (TCP) activo en el puerto " + puertoTcp,
                "Cualquier equipo de la red Wi-Fi podría intentar conectarse a la depuración de este teléfono.",
                "Desactívalo: reinicia el teléfono o apaga la depuración por USB y la inalámbrica.", "ADB"
            )
        }
        val su = ParserShell.existentes(m["su"] ?: "")
        if (su.isNotEmpty()) {
            datos.hallazgo(
                Riesgo.CRITICO, "Posible acceso root (archivo su encontrado)",
                "Se encontró: " + su.joinToString("; ").take(160) + ". Con root, cualquier app con permiso puede leer y modificar todo el sistema.",
                "Si no lo hiciste tú, restaura el teléfono de fábrica con el sistema oficial.", "ADB"
            )
        }
    }

    private fun ajustes(datos: DatosForenses, m: Map<String, String>) {
        val proxy = ParserShell.ajuste(m["ajuste_proxy"])
        if (proxy != null && proxy != ":0" && datos.hallazgos.none { it.titulo.startsWith("Proxy") }) {
            datos.hallazgo(
                Riesgo.ALTO, "Proxy global configurado (" + proxy + ")",
                "Todo el tráfico HTTP del teléfono pasa por ese equipo, que puede verlo y alterarlo.",
                "Si no lo pusiste tú, quítalo (Ajustes > Wi-Fi > red > Proxy) y revisa qué app o perfil lo configuró.", "ADB"
            )
        }
        val modoDns = ParserShell.ajuste(m["ajuste_dns_modo"])
        val hostDns = ParserShell.ajuste(m["ajuste_dns_host"])
        if (modoDns == "off" && datos.hallazgos.none { it.titulo.startsWith("DNS privado") }) {
            datos.hallazgo(
                Riesgo.BAJO, "DNS privado desactivado",
                "Las consultas DNS viajan sin cifrar y la red (o quien la controle) puede verlas o falsearlas.",
                "Actívalo en Ajustes > Red > DNS privado (por ejemplo con dns.google o one.one.one.one).", "ADB"
            )
        }
        if (ParserShell.ajuste(m["ajuste_verificador"]) == "0") {
            datos.hallazgo(
                Riesgo.MEDIO, "Verificación de apps desactivada",
                "package_verifier_enable=0: Play Protect no revisa las apps que se instalan.",
                "Actívalo en Google Play > Play Protect.", "ADB"
            )
        }
        if (ParserShell.ajuste(m["ajuste_verificador_adb"]) == "0") {
            datos.hallazgo(
                Riesgo.BAJO, "Las apps instaladas por ADB no se verifican",
                "Es habitual en móviles de desarrollo; permite instalar apps dañinas por cable sin aviso.",
                "Déjalo activado salvo que desarrolles apps.", "ADB"
            )
        }
        if (ParserShell.ajuste(m["ajuste_adb_wifi"]) == "1") {
            datos.hallazgo(
                Riesgo.BAJO, "Depuración inalámbrica activada",
                "Es lo que usa El Faro para este análisis. Mientras siga activa, quien consiga emparejarse con el código podría controlar el teléfono.",
                "Desactívala en Opciones de desarrollador al terminar.", "ADB"
            )
        }
        val vpn = ParserShell.ajuste(m["ajuste_vpn_siempre"])
        val lineas = ArrayList<String>()
        lineas.add("Proxy global: " + (if (proxy == null || proxy == ":0") "ninguno" else proxy))
        lineas.add("DNS privado: " + (modoDns ?: "automático") + (if (hostDns != null) " (" + hostDns + ")" else ""))
        lineas.add("VPN siempre activa: " + (vpn ?: "ninguna"))
        lineas.add("Depuración USB: " + (if (ParserShell.ajuste(m["ajuste_adb"]) == "1") "activada" else "desactivada"))
        lineas.add("Opciones de desarrollador: " + (if (ParserShell.ajuste(m["ajuste_desarrollo"]) == "1") "activadas" else "desactivadas"))
        datos.seccion("Ajustes de red y seguridad (ADB)", lineas)
    }

    private fun propietarios(datos: DatosForenses, m: Map<String, String>, apps: List<AppInfo>) {
        val etiquetas = apps.associate { it.paquete to it.etiqueta }
        val lista = ParserShell.propietarios(m["politica"] ?: "")
        for (p in lista.distinctBy { it.tipo + it.paquete }) {
            val nombre = etiquetas[p.paquete] ?: p.paquete
            datos.hallazgo(
                Riesgo.MEDIO, "Teléfono administrado por «" + nombre + "» (" + p.tipo.lowercase(Locale.ROOT) + ")",
                "Esa app puede aplicar políticas al teléfono (bloquear, borrar, restringir). Es normal en equipos de empresa; en uno personal es una señal a investigar, porque también la usa el software espía.",
                "Si no lo gestiona tu empresa o centro, averigua cómo se instaló y quítalo.", "ADB"
            )
        }
    }

    // ------------------------------------------------------------------ Wi-Fi

    private fun wifi(datos: DatosForenses, m: Map<String, String>, red: InfoRed) {
        val estado = ParserShell.wifiEstado(m["wifi"] ?: "")
        val aps = ParserShell.escaneo(m["escaneo"] ?: "")
        val guardadas = ParserShell.redesGuardadas(m["redes_guardadas"] ?: "")
        val lineas = ArrayList<String>()
        if (estado != null) {
            lineas.add("Red: " + (estado.ssid ?: red.ssid ?: "?") + " · BSSID " + (estado.bssid ?: "?"))
            if (estado.tipoSeguridad != null) lineas.add("Cifrado (leído sin ubicación): " + etiquetaTipoSeguridad(estado.tipoSeguridad))
            val f = estado.frecuenciaMhz
            if (f != null) lineas.add("Banda " + ParserShell.banda(f) + " · canal " + ParserShell.canal(f))
            val extra = ArrayList<String>()
            if (estado.rssi != null) extra.add("señal " + estado.rssi + " dBm")
            if (estado.velocidadMbps != null) extra.add(estado.velocidadMbps.toString() + " Mbps")
            if (estado.estandar != null) extra.add(estandarWifi(estado.estandar))
            if (extra.isNotEmpty()) lineas.add(extra.joinToString(" · "))
            if (estado.tipoSeguridad == 0 && red.seguridad != com.vigia.faro.Seguridad.ABIERTA) {
                datos.hallazgo(
                    Riesgo.CRITICO, "La red Wi-Fi es abierta (detectado por ADB)",
                    "Android reporta seguridad «abierta» para esta red: cualquiera puede conectarse y espiar lo que no vaya cifrado.",
                    "Evita datos sensibles y usa una VPN. En tu router, activa WPA2 o WPA3.", "ADB"
                )
            } else if (estado.tipoSeguridad == 1) {
                datos.hallazgo(
                    Riesgo.CRITICO, "Cifrado WEP (detectado por ADB)", "WEP se rompe en minutos con herramientas públicas.",
                    "Cambia el router a WPA2 o WPA3.", "ADB"
                )
            }
        } else {
            datos.limitaciones.add("ADB no devolvió el estado Wi-Fi (cmd wifi status).")
        }

        if (aps.isNotEmpty()) {
            val porSsid = aps.filter { it.ssid.isNotEmpty() }.groupBy { it.ssid }
            val abiertas = porSsid.count { entry -> entry.value.all { ParserShell.claseSeguridad(it.flags) == "ABIERTA" } }
            lineas.add("Redes cercanas: " + porSsid.size + " (" + abiertas + " abiertas) · " + aps.size + " puntos de acceso")
            val miSsid = estado?.ssid ?: red.ssid
            val miBssid = estado?.bssid ?: red.bssid
            if (miSsid != null) {
                val grupo = porSsid[miSsid] ?: emptyList()
                if (grupo.size >= 2) {
                    val clases = grupo.map { ParserShell.claseSeguridad(it.flags) }.toSet()
                    val hayDebil = clases.any { ParserShell.esDebil(it) }
                    val hayFuerte = clases.any { !ParserShell.esDebil(it) }
                    val prefijoMio = Oui.prefijo(miBssid)
                    val otrosFabricantes = grupo.filter { Oui.prefijo(it.bssid) != null && prefijoMio != null && Oui.prefijo(it.bssid) != prefijoMio }
                    lineas.add("Puntos de acceso con el nombre «" + miSsid + "»: " + grupo.size + " (" + clases.joinToString(", ") + ")")
                    if (hayDebil && hayFuerte) {
                        datos.hallazgo(
                            Riesgo.ALTO, "Posible gemelo malvado: «" + miSsid + "» se ofrece con cifrados distintos",
                            "Hay puntos de acceso con el mismo nombre, unos protegidos y otros débiles o abiertos (" + clases.joinToString(", ") + "). Un atacante puede imitar tu red para que el teléfono se conecte a la suya.",
                            "Comprueba el BSSID de tu router (aparece en el panel del router) y no te conectes a la variante abierta.", "ADB"
                        )
                    } else if (otrosFabricantes.isNotEmpty()) {
                        datos.hallazgo(
                            Riesgo.BAJO, "Puntos de acceso de distintos fabricantes con el mismo nombre",
                            otrosFabricantes.size.toString() + " punto(s) de acceso con el nombre «" + miSsid + "» tienen un prefijo de MAC distinto al tuyo. Es normal con repetidores o routers mixtos; también lo sería con una red falsa.",
                            "Si no tienes repetidores, revisa de dónde sale esa señal.", "ADB"
                        )
                    }
                }
            }
        } else if (estado != null) {
            datos.limitaciones.add("ADB no devolvió el escaneo de redes cercanas: no se pudo comprobar si hay gemelos malvados.")
        }

        if (guardadas.isNotEmpty()) {
            val abiertas = guardadas.filter { it.seguridad.contains("open") || it.seguridad == "none" }
            lineas.add("Redes guardadas: " + guardadas.size + " (" + abiertas.size + " abiertas)")
            if (abiertas.isNotEmpty()) {
                datos.hallazgo(
                    Riesgo.BAJO, abiertas.size.toString() + " red(es) abierta(s) guardada(s) en el teléfono",
                    "El móvil se conecta solo a ellas cuando las ve, y un atacante puede imitarlas (" + abiertas.take(5).joinToString(", ") { it.ssid } + ").",
                    "Olvida las redes abiertas que ya no uses (Ajustes > Wi-Fi > Redes guardadas).", "ADB"
                )
            }
        }
        datos.seccion("Wi-Fi (ADB)", lineas)
    }

    // ------------------------------------------------------------------ tabla ARP

    private fun vecinos(datos: DatosForenses, m: Map<String, String>, red: InfoRed) {
        val todos = ParserShell.vecinos(m["vecinos"] ?: "")
        if (todos.isEmpty()) return
        val v4 = todos.filter { it.ip.contains('.') && it.mac != null }
        val lineas = ArrayList<String>()
        for (v in v4.sortedBy { (UtilRed.parseIpv4(it.ip) ?: 0).toLong() and 0xFFFFFFFFL }) {
            val fab = Oui.buscar(v.mac)
            val aleatoria = Oui.esAleatoria(v.mac)
            lineas.add(v.ip + " → " + v.mac + (if (fab != null) " (" + fab + ")" else if (aleatoria) " (MAC aleatoria)" else "") + " " + v.estado)
        }
        datos.seccion("Tabla ARP (" + v4.size + " equipos)", lineas)

        val gateway = red.gateway
        val macRouter = if (gateway != null) v4.firstOrNull { it.ip == gateway }?.mac else null
        if (macRouter != null) {
            val otrasIp = v4.filter { it.mac == macRouter && it.ip != gateway }.map { it.ip }
            if (otrasIp.isNotEmpty()) {
                datos.hallazgo(
                    Riesgo.ALTO, "La MAC del router aparece también en otras IP (posible ARP spoofing)",
                    "La MAC " + macRouter + " responde por " + gateway + " y por " + otrasIp.joinToString(", ") + ". Es lo que ocurre cuando un equipo se hace pasar por el router para interceptar el tráfico (aunque algunos routers con varias redes también lo hacen).",
                    "Comprueba en el panel del router cuál es su MAC y qué equipo tiene esas otras IP. Evita datos sensibles hasta aclararlo.", "ADB"
                )
            }
            val bssid = red.bssid
            val pm = Oui.prefijo(macRouter)
            val pb = Oui.prefijo(bssid)
            if (bssid != null && pm != null && pb != null && pm != pb) {
                datos.hallazgo(
                    Riesgo.BAJO, "El router y el punto de acceso tienen MAC de distinto fabricante",
                    "Router " + macRouter + (Oui.buscar(macRouter)?.let { " (" + it + ")" } ?: "") + " y Wi-Fi " + bssid + (Oui.buscar(bssid)?.let { " (" + it + ")" } ?: "") +
                        ". Es normal si hay un punto de acceso o repetidor aparte; en una red de un solo equipo no debería pasar.",
                    "Si tu router y tu Wi-Fi son el mismo aparato, compara estas MAC con las que indica su etiqueta.", "ADB"
                )
            }
        }
        val porMac = v4.filter { it.ip != gateway && !it.ip.endsWith(".255") }.groupBy { it.mac }
        for ((mac, lista) in porMac) {
            if (lista.size >= 3) {
                datos.hallazgo(
                    Riesgo.BAJO, "Un mismo equipo responde por " + lista.size + " IP (" + mac + ")",
                    "Puede ser un puente, un repetidor, un servidor con varias direcciones o una suplantación ARP: " + lista.take(6).joinToString(", ") { it.ip } + ".",
                    "Identifica qué equipo es (en el panel del router, lista de dispositivos).", "ADB"
                )
            }
        }
        val aleatorias = v4.count { Oui.esAleatoria(it.mac) }
        if (aleatorias > 0) {
            datos.hallazgo(
                Riesgo.INFO, aleatorias.toString() + " equipo(s) usan MAC aleatoria",
                "Los móviles modernos cambian su MAC por red (o cada cierto tiempo, iPhone) para que no los rastreen. Por eso un «NUEVO» puede ser un móvil conocido con otra MAC.",
                "Nada que hacer.", "ADB"
            )
        }
    }

    // ------------------------------------------------------------------ sockets del teléfono

    private fun conexiones(c: Context, datos: DatosForenses, m: Map<String, String>, apps: List<AppInfo>, indicadores: Set<String>) {
        val todas = ArrayList<ParserShell.Conexion>()
        todas.addAll(ParserShell.conexiones(m["tcp4"] ?: "", "tcp4"))
        todas.addAll(ParserShell.conexiones(m["tcp6"] ?: "", "tcp6"))
        todas.addAll(ParserShell.conexiones(m["udp4"] ?: "", "udp4"))
        todas.addAll(ParserShell.conexiones(m["udp6"] ?: "", "udp6"))
        if (todas.isEmpty()) {
            datos.limitaciones.add("ADB no devolvió las conexiones del teléfono (/proc/net).")
            return
        }
        val etiquetas = apps.associate { it.paquete to it.etiqueta }
        val sistemas = apps.filter { it.sistema }.map { it.paquete }.toSet()
        val cache = HashMap<Int, Pair<String, Boolean>>()
        fun dueno(uid: Int): Pair<String, Boolean> {
            return cache.getOrPut(uid) {
                when (uid) {
                    0 -> Pair("root", true)
                    1000 -> Pair("sistema Android", true)
                    2000 -> Pair("shell (ADB)", true)
                    else -> {
                        val nombres = try { c.packageManager.getPackagesForUid(uid) } catch (e: Exception) { null }
                        val p = nombres?.firstOrNull()
                        if (p == null) Pair("uid " + uid, true)
                        else Pair((etiquetas[p] ?: p) + " (" + p + ")", sistemas.contains(p))
                    }
                }
            }
        }

        val establecidas = todas.filter { it.establecida && !esLoopback(it.remotoIp) }
        val porApp = establecidas.groupBy { it.uid }
        val lineas = ArrayList<String>()
        lineas.add(establecidas.size.toString() + " conexiones TCP establecidas · " + todas.count { it.escuchando && it.protocolo.startsWith("tcp") } + " puertos TCP en escucha")
        for ((uid, lista) in porApp.entries.sortedByDescending { it.value.size }.take(14)) {
            val remotos = lista.map { it.remotoIp + ":" + it.remotoPuerto }.distinct().take(3).joinToString(", ")
            lineas.add("• " + dueno(uid).first + ": " + lista.size + " → " + remotos + (if (lista.map { it.remotoIp }.distinct().size > 3) "…" else ""))
        }
        datos.seccion("Conexiones del teléfono (ADB)", lineas)

        // Indicadores de compromiso: IP remotas conocidas.
        if (indicadores.isNotEmpty()) {
            for (cx in establecidas) {
                if (indicadores.contains(cx.remotoIp.lowercase())) {
                    datos.hallazgo(
                        Riesgo.CRITICO, "Conexión a un indicador de compromiso: " + cx.remotoIp,
                        dueno(cx.uid).first + " tiene una conexión abierta con " + cx.remotoIp + ":" + cx.remotoPuerto + ", que figura en tu lista de indicadores.",
                        "Desinstala o desactiva esa app y repite el análisis. Conserva la evidencia firmada.", "IOC"
                    )
                }
            }
        }

        // Apps que no son del sistema y aceptan conexiones desde la red.
        val escuchas = todas.filter {
            it.escuchando && it.protocolo.startsWith("tcp") && !esLoopback(it.localIp)
        }
        val avisadas = HashSet<String>()
        for (e in escuchas) {
            val d = dueno(e.uid)
            // Los servicios del sistema (incluida la depuración inalámbrica) ya se informan aparte.
            if (d.second) continue
            val clave = d.first + e.localPuerto
            if (!avisadas.add(clave)) continue
            datos.hallazgo(
                Riesgo.MEDIO, d.first + " acepta conexiones de la red (puerto " + e.localPuerto + ")",
                "Una app que no es del sistema escucha en una dirección accesible desde el Wi-Fi. Lo hacen servidores de archivos, de pantalla o de control remoto, y también algunas apps espía.",
                "Comprueba que reconoces la app y que necesitas esa función; si no, desinstálala.", "ADB"
            )
        }
    }

    // ------------------------------------------------------------------ apps con accesos especiales

    private val PERMISOS_SENSIBLES = setOf(
        "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "READ_SMS", "RECEIVE_SMS",
        "SEND_SMS", "READ_CALL_LOG", "READ_CONTACTS", "READ_PHONE_STATE", "MANAGE_EXTERNAL_STORAGE", "READ_PHONE_NUMBERS"
    )

    private fun appsProfundo(datos: DatosForenses, m: Map<String, String>, apps: List<AppInfo>) {
        val lineas = ArrayList<String>()
        for (a in RecolectorAdb.elegirApps(apps)) {
            val salidaPkg = m["pkg_" + a.paquete] ?: continue
            val det = ParserShell.detallePaquete(salidaPkg)
            val sensibles = det.permisosConcedidos.map { it.substringAfterLast('.') }.filter { PERMISOS_SENSIBLES.contains(it) }
            val usos = ParserShell.appops(m["ops_" + a.paquete] ?: "")
            lineas.add("• " + a.etiqueta + " (" + a.paquete + ")")
            val motivos = ArrayList<String>()
            if (a.accesibilidad) motivos.add("accesibilidad")
            if (a.administrador) motivos.add("administrador")
            if (a.lectorNotificaciones) motivos.add("lee notificaciones")
            if (a.teclado) motivos.add("teclado")
            if (motivos.isNotEmpty()) lineas.add("   Acceso especial: " + motivos.joinToString(", "))
            lineas.add("   Instalada: " + (det.primeraInstalacion ?: "?") + " · actualizada: " + (det.ultimaActualizacion ?: "?") + " · origen: " + (det.instalador ?: (if (a.instalador.isEmpty()) "desconocido" else a.instalador)))
            if (sensibles.isNotEmpty()) lineas.add("   Permisos sensibles concedidos: " + sensibles.joinToString(", "))

            val recientes = ArrayList<Pair<String, Long>>()
            for (u in usos) {
                val ms = u.haceMs ?: continue
                if (u.modo != "allow") continue
                if (u.op == "CAMERA" || u.op == "RECORD_AUDIO" || u.op == "FINE_LOCATION" || u.op == "COARSE_LOCATION" ||
                    u.op == "READ_SMS" || u.op == "READ_CONTACTS" || u.op == "READ_CALL_LOG"
                ) {
                    recientes.add(Pair(u.op, ms))
                }
            }
            for ((op, ms) in recientes.sortedBy { it.second }) {
                lineas.add("   Último uso de " + nombreOp(op) + ": hace " + hace(ms))
                if (ms <= 24L * 3_600_000L) {
                    val sensor = op == "CAMERA" || op == "RECORD_AUDIO"
                    datos.hallazgo(
                        if (sensor) Riesgo.MEDIO else Riesgo.BAJO,
                        a.etiqueta + " usó " + nombreOp(op) + " hace " + hace(ms),
                        "Es una app con accesos especiales (" + (if (motivos.isEmpty()) "puntuación de riesgo alta" else motivos.joinToString(", ")) + ") y accedió a este recurso en las últimas 24 horas.",
                        "Comprueba que la usaste tú en ese momento. Si no la reconoces, desinstálala.", "ADB"
                    )
                }
            }
        }
        datos.seccion("Apps con accesos especiales, en detalle (ADB)", lineas)
    }

    private fun nombreOp(op: String): String {
        return when (op) {
            "CAMERA" -> "la cámara"
            "RECORD_AUDIO" -> "el micrófono"
            "FINE_LOCATION" -> "la ubicación precisa"
            "COARSE_LOCATION" -> "la ubicación aproximada"
            "READ_SMS" -> "los SMS"
            "READ_CONTACTS" -> "los contactos"
            "READ_CALL_LOG" -> "el registro de llamadas"
            else -> op
        }
    }

    // ------------------------------------------------------------------ archivos

    private fun archivos(datos: DatosForenses, m: Map<String, String>) {
        val lista = (m["apks"] ?: "").lines().map { it.trim() }.filter { it.endsWith(".apk", ignoreCase = true) && it.startsWith("/") }
        if (lista.isNotEmpty()) {
            datos.hallazgo(
                Riesgo.BAJO, lista.size.toString() + " archivo(s) APK en el almacenamiento",
                "Instaladores de apps fuera de las tiendas: " + lista.take(5).joinToString(", ") { it.substringAfterLast('/') } + ". Es una vía habitual para instalar software espía.",
                "Borra los que no reconozcas y no instales apps de fuentes desconocidas.", "ADB"
            )
            datos.seccion("APK encontrados (ADB)", lista.take(20))
        }
    }
}
