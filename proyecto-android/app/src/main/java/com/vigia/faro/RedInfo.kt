package com.vigia.faro

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import java.net.Inet4Address

enum class Seguridad(val etiqueta: String) {
    ABIERTA("Abierta (sin contraseña)"),
    WEP("WEP (obsoleta)"),
    WPA("WPA (antigua)"),
    WPA2("WPA2"),
    WPA3("WPA3"),
    OWE("Abierta con cifrado (OWE)"),
    EMPRESA("Empresarial (802.1X)"),
    DESCONOCIDA("No disponible")
}

class InfoRed(
    val conectada: Boolean,
    val esWifi: Boolean,
    val ssid: String?,
    val bssid: String?,
    val seguridad: Seguridad,
    val ipLocal: String?,
    val prefijo: Int,
    val gateway: String?,
    val dns: List<String>,
    /** Android ya marcó esta red como «con portal cautivo». */
    val portalMarcado: Boolean,
    val faltaUbicacion: Boolean
) {
    /** Clave estable de la red para recordar sus dispositivos. */
    val idRed: String get() = (gateway ?: "") + "|" + (bssid ?: ssid ?: "")
}

object LectorRed {

    @Suppress("DEPRECATION")
    fun leer(c: Context): InfoRed {
        val app = c.applicationContext
        val cm = app.getSystemService(ConnectivityManager::class.java)
        val red = cm.activeNetwork
        val caps = if (red != null) cm.getNetworkCapabilities(red) else null
        val lp = if (red != null) cm.getLinkProperties(red) else null
        val esWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        val conectada = caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)

        var ip: String? = null
        var prefijo = 24
        var gateway: String? = null
        val dns = ArrayList<String>()
        if (lp != null) {
            for (la in lp.linkAddresses) {
                val a = la.address
                if (a is Inet4Address && ip == null) {
                    ip = a.hostAddress
                    prefijo = la.prefixLength
                }
            }
            for (r in lp.routes) {
                val g = r.gateway
                if (r.isDefaultRoute && g is Inet4Address && gateway == null) gateway = g.hostAddress
            }
            for (d in lp.dnsServers) {
                if (d is Inet4Address) dns.add(d.hostAddress ?: continue)
            }
        }

        var ssid: String? = null
        var bssid: String? = null
        var seguridad = Seguridad.DESCONOCIDA
        val tieneUbicacion = ContextCompat.checkSelfPermission(app, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (esWifi) {
            try {
                val wm = app.getSystemService(Context.WIFI_SERVICE) as WifiManager
                val wi = wm.connectionInfo
                val s = wi?.ssid?.trim('"')
                if (s != null && s.isNotEmpty() && s != "<unknown ssid>") ssid = s
                val b = wi?.bssid
                if (b != null && b != "02:00:00:00:00:00") bssid = b
                seguridad = if (Build.VERSION.SDK_INT >= 31 && wi != null) {
                    desdeTipo(wi.currentSecurityType)
                } else {
                    desdeEscaneo(wm, bssid, tieneUbicacion)
                }
            } catch (e: Exception) {
            }
        }
        return InfoRed(
            conectada = conectada, esWifi = esWifi, ssid = ssid, bssid = bssid, seguridad = seguridad,
            ipLocal = ip, prefijo = prefijo, gateway = gateway, dns = dns,
            portalMarcado = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true,
            faltaUbicacion = esWifi && !tieneUbicacion
        )
    }

    /** Valores de WifiInfo.SECURITY_TYPE_* (Android 12+). */
    private fun desdeTipo(t: Int): Seguridad {
        return when (t) {
            0 -> Seguridad.ABIERTA
            1 -> Seguridad.WEP
            2 -> Seguridad.WPA2
            3, 5, 9, 10 -> Seguridad.EMPRESA
            4 -> Seguridad.WPA3
            6 -> Seguridad.OWE
            else -> Seguridad.DESCONOCIDA
        }
    }

    /** Android 11 o menos: se deduce de las «capabilities» del punto de acceso en el último escaneo (requiere ubicación). */
    @Suppress("DEPRECATION")
    private fun desdeEscaneo(wm: WifiManager, bssid: String?, tieneUbicacion: Boolean): Seguridad {
        if (!tieneUbicacion || bssid == null) return Seguridad.DESCONOCIDA
        val encontrada: String? = try {
            wm.scanResults.firstOrNull { it.BSSID.equals(bssid, ignoreCase = true) }?.capabilities
        } catch (e: Exception) {
            null
        }
        val cap = encontrada ?: return Seguridad.DESCONOCIDA
        return when {
            cap.contains("EAP") -> Seguridad.EMPRESA
            cap.contains("SAE") -> Seguridad.WPA3
            cap.contains("OWE") -> Seguridad.OWE
            cap.contains("WEP") -> Seguridad.WEP
            cap.contains("WPA2") || cap.contains("RSN") -> Seguridad.WPA2
            cap.contains("WPA") -> Seguridad.WPA
            else -> Seguridad.ABIERTA
        }
    }
}
