package com.vigia.faro.forense

import com.vigia.core.inventario.AppInfo
import com.vigia.faro.adb.GestorAdb

/**
 * Recoge con ADB (en este mismo teléfono) lo que una app normal no puede ver: tabla ARP, red Wi-Fi sin pedir ubicación,
 * sockets del teléfono con su app propietaria, administración del dispositivo, propiedades del sistema, etc.
 * SOLO LEE: no cambia ningún ajuste ni toca ningún dato personal (no se leen mensajes, notificaciones ni archivos).
 */
object RecolectorAdb {

    private val ORDENES: List<Pair<String, String>> = listOf(
        "identidad" to "id",
        "fecha" to "date +%s",
        "kernel" to "uname -a",
        "vecinos" to "ip neigh show",
        "vecinos6" to "ip -6 neigh show",
        "rutas" to "ip route show table all",
        "direcciones" to "ip addr show",
        "wifi" to "cmd wifi status",
        "escaneo" to "cmd wifi list-scan-results",
        "redes_guardadas" to "cmd wifi list-networks",
        "tcp4" to "cat /proc/net/tcp",
        "tcp6" to "cat /proc/net/tcp6",
        "udp4" to "cat /proc/net/udp",
        "udp6" to "cat /proc/net/udp6",
        "props" to "getprop",
        "ajuste_proxy" to "settings get global http_proxy",
        "ajuste_dns_modo" to "settings get global private_dns_mode",
        "ajuste_dns_host" to "settings get global private_dns_specifier",
        "ajuste_adb" to "settings get global adb_enabled",
        "ajuste_adb_wifi" to "settings get global adb_wifi_enabled",
        "ajuste_desarrollo" to "settings get global development_settings_enabled",
        "ajuste_verificador" to "settings get global package_verifier_enable",
        "ajuste_verificador_adb" to "settings get global verifier_verify_adb_installs",
        "ajuste_vpn_siempre" to "settings get secure always_on_vpn_app",
        "politica" to "dumpsys device_policy",
        "su" to "ls -l /system/bin/su /system/xbin/su /sbin/su /system_ext/bin/su /vendor/bin/su /system/app/Superuser.apk",
        "apks" to "find /sdcard/Download /sdcard/Documents /sdcard/DCIM -maxdepth 2 -iname *.apk"
    )

    private val NOMBRE_PAQUETE = Regex("^[A-Za-z0-9_.]+$")

    /** Apps que merecen mirarse con más detalle: accesos especiales o puntuación de riesgo alta. */
    fun elegirApps(apps: List<AppInfo>): List<AppInfo> {
        return apps
            .filter { !it.sistema && NOMBRE_PAQUETE.matches(it.paquete) }
            .filter { it.accesibilidad || it.administrador || it.lectorNotificaciones || it.teclado || it.nivel == "revisar" }
            .sortedByDescending { it.puntos }
            .take(8)
    }

    /** Devuelve la salida de cada orden por identificador, y guarda cada una como prueba en [datos]. */
    suspend fun recolectar(apps: List<AppInfo>, datos: DatosForenses, progreso: (String) -> Unit): Map<String, String> {
        val ordenes = LinkedHashMap<String, String>()
        for ((id, orden) in ORDENES) ordenes[id] = orden

        progreso("Modo avanzado: leyendo el sistema (ARP, Wi-Fi, conexiones…)")
        val res = LinkedHashMap<String, String>()
        res.putAll(GestorAdb.ejecutarLote(ORDENES, 90_000L))

        val sospechosas = elegirApps(apps)
        if (sospechosas.isNotEmpty()) {
            progreso("Modo avanzado: revisando " + sospechosas.size + " app(s) con accesos especiales…")
            val extra = ArrayList<Pair<String, String>>()
            for (a in sospechosas) {
                extra.add(("pkg_" + a.paquete) to ("dumpsys package " + a.paquete))
                extra.add(("ops_" + a.paquete) to ("cmd appops get " + a.paquete))
            }
            for ((id, orden) in extra) ordenes[id] = orden
            res.putAll(GestorAdb.ejecutarLote(extra, 60_000L))
        }

        datos.adbUsado = true
        for ((id, salida) in res) datos.artefacto(id, ordenes[id] ?: id, salida)
        if (res["vecinos"].isNullOrBlank()) {
            datos.limitaciones.add("ADB no devolvió la tabla ARP: este teléfono o versión de Android no permite leerla con ip neigh.")
        }
        return res
    }
}
