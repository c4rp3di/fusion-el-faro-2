package com.vigia.faro.forense

import com.vigia.faro.Riesgo

/**
 * Comprueba las versiones que anuncian los equipos (banners SSH/FTP/HTTP, cabecera de UPnP, versión del DNS) contra un
 * conjunto PEQUEÑO y revisado a mano de casos muy conocidos: puertas traseras, fallos famosos y software sin soporte.
 * No es una base de datos de CVE: que no salga nada no significa que el equipo esté al día, y los fabricantes a veces
 * corrigen un fallo sin cambiar el número de versión (falso positivo posible).
 */
object Versiones {

    class Aviso(val riesgo: Riesgo, val producto: String, val detalle: String)

    private fun cmp(a: IntArray, b: IntArray): Int {
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = if (i < a.size) a[i] else 0
            val y = if (i < b.size) b[i] else 0
            if (x != y) return if (x < y) -1 else 1
        }
        return 0
    }

    private fun nums(vararg t: String?): IntArray = t.filterNotNull().mapNotNull { it.toIntOrNull() }.toIntArray()

    fun evaluar(texto: String): List<Aviso> {
        val res = ArrayList<Aviso>()
        val t = texto

        Regex("""OpenSSH[_ ](\d+)\.(\d+)""").find(t)?.also { m ->
            val v = nums(m.groupValues[1], m.groupValues[2])
            val nombre = "OpenSSH " + m.groupValues[1] + "." + m.groupValues[2]
            if (cmp(v, intArrayOf(7, 0)) < 0) {
                res.add(Aviso(Riesgo.MEDIO, nombre, "Es una versión de 2015 o anterior, sin soporte. Acumula fallos de seguridad corregidos después."))
            } else if (cmp(v, intArrayOf(7, 8)) < 0) {
                res.add(Aviso(Riesgo.BAJO, nombre, "Hasta la 7.7 inclusive permite averiguar qué usuarios existen (CVE-2018-15473)."))
            }
        }
        Regex("""dropbear_(\d{4})\.(\d+)""", RegexOption.IGNORE_CASE).find(t)?.also { m ->
            val anio = m.groupValues[1].toInt()
            val nombre = "Dropbear " + m.groupValues[1] + "." + m.groupValues[2]
            if (anio < 2017) {
                res.add(Aviso(Riesgo.MEDIO, nombre, "Versión de 2016 o anterior: hay correcciones de seguridad posteriores."))
            } else if (anio < 2020) {
                res.add(Aviso(Riesgo.BAJO, nombre, "Versión anterior a 2020: hay correcciones de seguridad posteriores."))
            }
        }
        if (Regex("""^SSH-1\.(?!99)""", RegexOption.MULTILINE).containsMatchIn(t) || t.contains("SSH-1.5")) {
            res.add(Aviso(Riesgo.ALTO, "SSH protocolo 1", "El protocolo SSH 1 está roto desde hace décadas y no debería usarse."))
        }
        if (Regex("""vsFTPd 2\.3\.4""", RegexOption.IGNORE_CASE).containsMatchIn(t)) {
            res.add(Aviso(Riesgo.CRITICO, "vsftpd 2.3.4", "Esa versión tuvo una puerta trasera en su código fuente en 2011 (CVE-2011-2523): permite ejecutar órdenes sin contraseña."))
        }
        if (Regex("""ProFTPD 1\.3\.3c""", RegexOption.IGNORE_CASE).containsMatchIn(t)) {
            res.add(Aviso(Riesgo.CRITICO, "ProFTPD 1.3.3c", "El código fuente de esa versión se distribuyó con una puerta trasera en 2010."))
        }
        Regex("""Apache/(\d+)\.(\d+)\.?(\d+)?""").find(t)?.also { m ->
            val mayor = m.groupValues[1].toInt()
            val menor = m.groupValues[2].toInt()
            val parche = m.groupValues[3].toIntOrNull() ?: -1
            val nombre = "Apache " + m.groupValues[1] + "." + m.groupValues[2] + (if (parche >= 0) "." + parche else "")
            if (mayor == 2 && menor == 4 && parche == 49) {
                res.add(Aviso(Riesgo.CRITICO, nombre, "Tiene un fallo de recorrido de rutas que permite leer archivos y ejecutar código (CVE-2021-41773)."))
            } else if (mayor == 2 && menor == 4 && parche == 50) {
                res.add(Aviso(Riesgo.CRITICO, nombre, "La corrección de la 2.4.49 fue incompleta y sigue permitiendo ejecutar código (CVE-2021-42013)."))
            } else if (mayor < 2 || (mayor == 2 && menor <= 2)) {
                res.add(Aviso(Riesgo.MEDIO, nombre, "La rama " + mayor + "." + menor + " dejó de recibir actualizaciones (2.2 en 2017, 2.0 en 2013)."))
            }
        }
        Regex("""Microsoft-IIS/(\d+)\.(\d+)""").find(t)?.also { m ->
            val mayor = m.groupValues[1].toInt()
            if (mayor <= 7) {
                res.add(Aviso(Riesgo.MEDIO, "IIS " + m.groupValues[1] + "." + m.groupValues[2], "Esa versión de IIS no recibe actualizaciones desde 2015 (6.0) o 2020 (7.x)."))
            }
        }
        Regex("""OpenSSL/(\d+\.\d+\.\d+)([a-z]?)""").find(t)?.also { m ->
            val v = m.groupValues[1]
            val letra = m.groupValues[2]
            val nombre = "OpenSSL " + v + letra
            if (v == "1.0.1" && (letra.isEmpty() || letra[0] <= 'f')) {
                res.add(Aviso(Riesgo.CRITICO, nombre, "Afectado por Heartbleed (CVE-2014-0160): permite leer memoria del servidor, incluidas claves y contraseñas."))
            } else if (v.startsWith("0.9.8") || v.startsWith("1.0.0") || v.startsWith("1.0.1") || v.startsWith("1.0.2")) {
                res.add(Aviso(Riesgo.MEDIO, nombre, "Rama de OpenSSL sin soporte desde 2015-2019."))
            }
        }
        Regex("""Portable SDK for UPnP devices/(\d+)\.(\d+)\.(\d+)""", RegexOption.IGNORE_CASE).find(t)?.also { m ->
            val v = nums(m.groupValues[1], m.groupValues[2], m.groupValues[3])
            val nombre = "libupnp " + m.groupValues[1] + "." + m.groupValues[2] + "." + m.groupValues[3]
            if (cmp(v, intArrayOf(1, 6, 18)) < 0) {
                res.add(Aviso(Riesgo.ALTO, nombre, "Anterior a la 1.6.18: desbordamientos de memoria que permiten tomar el control del equipo desde la red (CVE-2012-5958 y siguientes, 2013)."))
            } else if (cmp(v, intArrayOf(1, 12, 1)) < 0) {
                res.add(Aviso(Riesgo.BAJO, nombre, "Anterior a la 1.12.1: afectada por «CallStranger» (CVE-2020-12695), que permite usar el equipo para atacar a terceros."))
            }
        }
        Regex("""MiniUPnPd/(\d+)\.(\d+)""", RegexOption.IGNORE_CASE).find(t)?.also { m ->
            val v = nums(m.groupValues[1], m.groupValues[2])
            if (cmp(v, intArrayOf(1, 4)) < 0) {
                res.add(Aviso(Riesgo.ALTO, "MiniUPnPd " + m.groupValues[1] + "." + m.groupValues[2], "Anterior a la 1.4: tiene un desbordamiento de pila conocido (2013)."))
            }
        }
        Regex("""dnsmasq-(\d+)\.(\d+)""", RegexOption.IGNORE_CASE).find(t)?.also { m ->
            val v = nums(m.groupValues[1], m.groupValues[2])
            if (cmp(v, intArrayOf(2, 83)) < 0) {
                res.add(Aviso(Riesgo.MEDIO, "dnsmasq " + m.groupValues[1] + "." + m.groupValues[2], "Anterior a la 2.83: afectada por «DNSpooq» (CVE-2020-25681 a 25687), que permite envenenar la caché DNS."))
            }
        }
        return res
    }
}
