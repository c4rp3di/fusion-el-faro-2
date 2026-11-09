package com.vigia.faro.forense

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import com.vigia.faro.Riesgo

/** Datos de la conexión Wi-Fi y del servidor DHCP que Android entrega a cualquier app (sin ADB). */
object DetallesWifi {

    private fun ip(i: Int): String = (i and 0xFF).toString() + "." + ((i shr 8) and 0xFF) + "." + ((i shr 16) and 0xFF) + "." + ((i shr 24) and 0xFF)

    @Suppress("DEPRECATION")
    fun analizar(c: Context, datos: DatosForenses, gateway: String?) {
        val lineas = ArrayList<String>()
        try {
            val wm = c.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val wi = wm.connectionInfo
            if (wi != null) {
                val f = wi.frequency
                if (f > 0) lineas.add("Banda " + ParserShell.banda(f) + " · canal " + ParserShell.canal(f))
                val extra = ArrayList<String>()
                if (wi.rssi > -127) extra.add("señal " + wi.rssi + " dBm")
                if (wi.linkSpeed > 0) extra.add(wi.linkSpeed.toString() + " Mbps")
                if (Build.VERSION.SDK_INT >= 30) {
                    val e = wi.wifiStandard
                    when (e) {
                        4 -> extra.add("Wi-Fi 4 (n)")
                        5 -> extra.add("Wi-Fi 5 (ac)")
                        6 -> extra.add("Wi-Fi 6 (ax)")
                        8 -> extra.add("Wi-Fi 7 (be)")
                        else -> {}
                    }
                }
                if (extra.isNotEmpty()) lineas.add(extra.joinToString(" · "))
                if (wi.hiddenSSID) lineas.add("La red tiene el nombre oculto (no añade seguridad real).")
            }
            val d = wm.dhcpInfo
            if (d != null && d.serverAddress != 0) {
                val servidor = ip(d.serverAddress)
                lineas.add("Servidor DHCP: " + servidor + " · concesión " + d.leaseDuration + " s")
                if (gateway != null && servidor != gateway) {
                    datos.hallazgo(
                        Riesgo.BAJO, "El servidor DHCP (" + servidor + ") no es el router (" + gateway + ")",
                        "Quien reparte las direcciones decide también tu DNS y tu puerta de salida. Es normal con algunos routers en cascada o servidores DHCP propios; un DHCP falso es una forma de desviar el tráfico.",
                        "Comprueba qué equipo es " + servidor + ". Si no lo reconoces, avisa al administrador de la red.", "DHCP"
                    )
                }
            }
        } catch (e: Exception) {
        }
        datos.seccion("Wi-Fi y DHCP", lineas)
    }
}
