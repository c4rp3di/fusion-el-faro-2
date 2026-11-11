package com.vigia.faro

import android.content.Context
import com.vigia.core.inventario.AppInfo
import com.vigia.core.inventario.AppsDispositivo
import com.vigia.core.red.UtilRed
import com.vigia.faro.adb.GestorAdb
import com.vigia.faro.forense.AnalisisAdb
import com.vigia.faro.forense.AnalisisUpnp
import com.vigia.faro.forense.CertDispositivo
import com.vigia.faro.forense.DatosForenses
import com.vigia.faro.forense.DetallesWifi
import com.vigia.faro.forense.Evidencia
import com.vigia.faro.forense.Huellas
import com.vigia.faro.forense.Indicadores
import com.vigia.faro.forense.Ipv6
import com.vigia.faro.forense.NatPmp
import com.vigia.faro.forense.Versiones
import com.vigia.faro.forense.WsDiscovery
import com.vigia.faro.forense.LineaBase
import com.vigia.faro.forense.Libro
import com.vigia.faro.forense.Oui
import com.vigia.faro.forense.ParserShell
import com.vigia.faro.forense.RecolectorAdb
import com.vigia.faro.forense.SondaDns
import com.vigia.faro.forense.SondaTls
import com.vigia.faro.forense.TelefonoForense
import com.vigia.faro.forense.Trazado
import com.vigia.faro.forense.UpnpAvanzado
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Qué se analiza. [forense] añade la revisión del propio teléfono, el modo avanzado (ADB, si está conectado), los indicadores
 * de compromiso y el historial firmado. [internet] permite las pruebas que salen a internet (DNS, TLS y traza).
 */
class Opciones(val completo: Boolean, val forense: Boolean, val internet: Boolean)

class ResultadoAnalisis(
    val red: InfoRed,
    val portal: ResultadoPortal,
    val router: Dispositivo?,
    val dispositivos: List<Dispositivo>,
    val upnpRouter: Boolean,
    val informe: Informe,
    val completo: Boolean,
    val momento: Long,
    val forense: DatosForenses? = null
) {
    /** JSON del informe, tal como se firma al exportarlo. */
    var evidencia: String = ""

    /** SHA-256 de [evidencia]. */
    var huellaEvidencia: String = ""
}

/** Ejecuta el análisis completo por fases y devuelve el informe. Se puede cancelar en cualquier momento. */
object Orquestador {

    private fun ipOrden(ip: String): Long = (UtilRed.parseIpv4(ip) ?: 0).toLong() and 0xFFFFFFFFL

    private fun esInfraestructura(r: RespuestaSsdp): Boolean {
        return r.st.contains("InternetGatewayDevice") || r.usn.contains("InternetGatewayDevice") || r.st.contains("WANIPConnection")
    }

    suspend fun analizar(c: Context, red: InfoRed, op: Opciones, progreso: (String) -> Unit): ResultadoAnalisis = coroutineScope {
        val app = c.applicationContext
        val completo = op.completo
        val gateway = red.gateway
        val datos = DatosForenses()

        val indicadores: Set<String> = if (op.forense) (Indicadores.cargar(app)?.valores ?: emptySet()) else emptySet()
        datos.indicadoresCargados = indicadores.size

        progreso("Comprobando si la red tiene portal cautivo…")
        val portal = if (red.esWifi) Portal.comprobar() else ResultadoPortal(EstadoPortal.NO_COMPROBADO, "No es una red Wi-Fi.")
        val enPortal = portal.estado == EstadoPortal.PORTAL || red.portalMarcado

        // UPnP y mDNS escuchan mientras se hace el resto.
        val ssdpTarea = async { Descubridor.ssdp(app, 3500L) }
        val mdnsTarea = if (completo) async { Descubridor.mdns(app, 7000L) } else null
        val wsdTarea = if (completo) async { WsDiscovery.descubrir(app, 3500L) } else null
        val ipv6Tarea = if (completo) async(Dispatchers.IO) { Ipv6.descubrir(Ipv6.nombreInterfaz(app)) } else null

        // Pruebas de red en paralelo. Cada una escribe en su propio DatosForenses para no mezclar hilos.
        val datosWifi = DatosForenses()
        val datosDns = DatosForenses()
        val datosTls = DatosForenses()
        val datosTraza = DatosForenses()
        val pruebasRed = async(Dispatchers.IO) {
            DetallesWifi.analizar(app, datosWifi, gateway)
            if (op.internet && red.esWifi) {
                val dns = async(Dispatchers.IO) { SondaDns.analizar(datosDns, red.dns) }
                val tls = async(Dispatchers.IO) { SondaTls.analizar(datosTls, enPortal) }
                val traza = async(Dispatchers.IO) { Trazado.analizar(datosTraza, gateway) }
                dns.await()
                tls.await()
                traza.await()
            } else if (red.esWifi) {
                datosDns.limitaciones.add("Pruebas con internet desactivadas: no se comprobaron el DNS, los certificados HTTPS ni la ruta.")
            }
            Unit
        }

        // ---- router
        val router: Dispositivo? = if (gateway != null) {
            progreso("Analizando el router (" + gateway + ")…")
            val r = Dispositivo(gateway)
            r.esRouter = true
            r.puertos.addAll(EscanerPuertos.escanear(gateway))
            r
        } else {
            null
        }
        val ssdp = ssdpTarea.await()
        val upnpRouter = gateway != null && ssdp.any { it.ip == gateway && esInfraestructura(it) }
        var ubicacionUpnp: String? = null
        if (router != null && gateway != null) {
            val rr = ssdp.firstOrNull { it.ip == gateway && it.ubicacion.isNotEmpty() }
            if (rr != null) {
                ubicacionUpnp = rr.ubicacion
                val desc = withContext(Dispatchers.IO) { Descubridor.descripcionUpnp(rr.ubicacion, gateway) }
                if (desc != null) {
                    router.nombre = router.nombre ?: desc.nombre
                    router.fabricante = desc.fabricante
                    router.modelo = desc.modelo
                }
            }
        }
        val ubicacionFinal = ubicacionUpnp
        val upnp: UpnpAvanzado.Resultado? = if (ubicacionFinal != null && gateway != null) {
            progreso("Leyendo los reenvíos de puertos del router (UPnP)…")
            withContext(Dispatchers.IO) { UpnpAvanzado.consultar(ubicacionFinal, gateway) }
        } else {
            null
        }

        // ---- comprobaciones UDP contra el propio router (solo lectura, no salen de la red local)
        var versionDnsRouter: String? = null
        if (gateway != null) {
            val natpmp = withContext(Dispatchers.IO) { NatPmp.consultar(gateway) }
            if (natpmp != null) {
                datos.hallazgo(
                    Riesgo.BAJO, "El router responde a NAT-PMP",
                    "Igual que UPnP, NAT-PMP permite que cualquier programa de la red pida al router que abra puertos hacia internet, sin contraseña. Su IP externa según NAT-PMP es " + natpmp.ipExterna + ".",
                    "Si no lo necesitas, desactiva UPnP y NAT-PMP en el router.", "UPnP"
                )
            }
            versionDnsRouter = withContext(Dispatchers.IO) { SondaDns.versionDns(gateway) }
        }

        // ---- teléfono (apps) y modo avanzado
        val apps: List<AppInfo> = if (op.forense) {
            withContext(Dispatchers.IO) {
                try {
                    AppsDispositivo.cargar(app)
                } catch (e: Exception) {
                    emptyList()
                }
            }
        } else {
            emptyList()
        }

        suspend fun recogerAdb(): Map<String, String>? {
            if (!op.forense) return null
            if (!GestorAdb.conectado) {
                datos.limitaciones.add("El modo avanzado (ADB) no está conectado: no se leyó la tabla ARP, el Wi-Fi sin ubicación ni las conexiones del teléfono.")
                return null
            }
            return try {
                RecolectorAdb.recolectar(apps, datos, progreso)
            } catch (e: Exception) {
                datos.limitaciones.add("Falló la lectura por ADB (" + (e.message ?: e.javaClass.simpleName) + "). Reconecta el modo avanzado.")
                null
            }
        }

        // ---- el resto de la red
        val lista = ArrayList<Dispositivo>()
        var salidaAdb: Map<String, String>? = null
        if (completo && red.ipLocal != null) {
            progreso("Buscando dispositivos…")
            val ips = Descubridor.rango(red.ipLocal, red.prefijo)
            val vivos = Descubridor.barrido(ips) { hechos, total -> progreso("Buscando dispositivos… " + hechos + "/" + total) }
            salidaAdb = recogerAdb()
            val vecinos = HashMap<String, String>(Descubridor.vecinos())
            if (salidaAdb != null) vecinos.putAll(AnalisisAdb.tablaIpv4(salidaAdb))
            val todos = HashSet<String>(vivos)
            for ((ip, _) in vecinos) if (ips.contains(ip)) todos.add(ip)
            for (r in ssdp) if (ips.contains(r.ip)) todos.add(r.ip)
            val servicios = mdnsTarea?.await() ?: emptyList()
            val wsd = wsdTarea?.await() ?: emptyList()
            for (r in wsd) if (ips.contains(r.ip)) todos.add(r.ip)
            for (s in servicios) if (ips.contains(s.ip)) todos.add(s.ip)
            todos.add(red.ipLocal)
            if (gateway != null) todos.add(gateway)

            for (ip in todos.sortedBy { ipOrden(it) }) {
                val d = if (router != null && ip == gateway) router else Dispositivo(ip)
                if (ip == red.ipLocal) d.esEsteTelefono = true
                d.mac = vecinos[ip]
                for (s in servicios) {
                    if (s.ip == ip) {
                        d.servicios.add(s.tipo + " " + s.nombre)
                        if (d.nombre == null && s.nombre.isNotEmpty()) d.nombre = s.nombre
                    }
                }
                for (r in wsd) if (r.ip == ip) d.servicios.add(WsDiscovery.resumen(r))
                for (r in ssdp) {
                    if (r.ip == ip) {
                        if (r.servidor.isNotEmpty()) d.servicios.add(r.servidor)
                        if (r.st.isNotEmpty()) d.servicios.add(r.st)
                    }
                }
                lista.add(d)
            }

            val sem = Semaphore(8)
            var terminados = 0
            val pendientes = lista.filter { it !== router }
            pendientes.map { d ->
                async(Dispatchers.IO) {
                    sem.withPermit {
                        if (d.nombre == null) {
                            d.nombre = withTimeoutOrNull(1500L) { async(Dispatchers.IO) { Descubridor.nombreInverso(d.ip) }.await() }
                        }
                        if (d.nombre == null) d.nombre = Descubridor.nombreNetbios(d.ip)
                        // El teléfono propio también se revisa: así se detecta un ADB por red abierto.
                        d.puertos.addAll(EscanerPuertos.escanear(d.ip, concurrencia = 10, timeoutMs = 600))
                        d.certInfo = certificadoDe(d)
                        val n = synchronized(pendientes) {
                            terminados++
                            terminados
                        }
                        progreso("Analizando dispositivos… " + n + "/" + pendientes.size)
                    }
                }
            }.awaitAll()
        } else {
            salidaAdb = recogerAdb()
            if (red.ipLocal != null && router != null) {
                val v = HashMap<String, String>(Descubridor.vecinos())
                if (salidaAdb != null) v.putAll(AnalisisAdb.tablaIpv4(salidaAdb))
                router.mac = v[router.ip]
                lista.add(router)
            }
        }
        if (router != null) router.certInfo = withContext(Dispatchers.IO) { certificadoDe(router) }

        // Fabricante según la MAC (solo si no se averiguó por UPnP) y clasificación.
        for (d in lista) if (d.fabricante == null) d.fabricante = Oui.buscar(d.mac)
        for (d in lista) Descubridor.clasificar(d)
        if (router != null && !lista.contains(router)) {
            Descubridor.clasificar(router)
        }

        // Nombres y marcas del usuario.
        val aNombrar = ArrayList<Dispositivo>(lista)
        if (router != null && !aNombrar.contains(router)) aNombrar.add(router)
        Alias.aplicar(app, aNombrar)

        // Versiones que anuncian los equipos (banners y cabeceras UPnP) frente a los casos conocidos.
        for (d in aNombrar) {
            val textos = ArrayList<String>()
            for (p in d.puertos) if (p.banner != null) textos.add(p.banner)
            textos.addAll(d.servicios)
            if (d.esRouter && versionDnsRouter != null) textos.add(versionDnsRouter)
            val vistos = HashSet<String>()
            val quien = if (d.esRouter) "el router" else d.nombreVisible + " (" + d.ip + ")"
            for (t in textos) {
                for (a in Versiones.evaluar(t)) {
                    if (!vistos.add(a.producto)) continue
                    datos.hallazgo(
                        a.riesgo, a.producto + " en " + quien,
                        a.detalle + " Se deduce de la versión que anuncia el equipo: algunos fabricantes corrigen el fallo sin cambiar el número.",
                        "Actualiza el firmware o el software del equipo. Si ya no tiene soporte, sustitúyelo o aíslalo de la red.", "Versiones"
                    )
                }
            }
        }
        if (versionDnsRouter != null) datos.seccion("DNS del router", listOf("Versión que anuncia: " + versionDnsRouter))

        // ---- dispositivos nuevos respecto a la última visita
        if (completo) {
            val previos = Conocidos.cargar(app, red.idRed)
            val actuales = ArrayList<String>()
            for (d in lista) {
                val id = d.mac ?: d.nombre
                if (id != null) {
                    actuales.add(id)
                    if (previos != null && !previos.contains(id) && !d.esEsteTelefono && !d.esRouter && !d.confiable) d.nuevo = true
                }
            }
            Conocidos.guardar(app, red.idRed, actuales)
        }

        // ---- resultados de las pruebas de red en paralelo
        progreso("Terminando las pruebas de red…")
        pruebasRed.await()
        datos.anadir(datosWifi)
        datos.anadir(datosDns)
        datos.anadir(datosTls)
        datos.anadir(datosTraza)

        // ---- IPv6 en la red local
        if (completo) {
            val respondieron = ipv6Tarea?.await() ?: emptyList()
            Ipv6.analizar(datos, respondieron, Ipv6.direccionesGlobales(app), salidaAdb, lista, gateway)
        }

        // ---- UPnP avanzado, certificados de equipos
        if (upnp != null) AnalisisUpnp.analizar(datos, upnp, lista.map { it.ip }.toSet())
        for (d in lista) {
            val ci = d.certInfo ?: continue
            val quien = if (d.esRouter) "el router" else d.nombreVisible + " (" + d.ip + ")"
            if (ci.caducado) {
                datos.hallazgo(
                    Riesgo.BAJO, "Certificado HTTPS caducado en " + quien,
                    "El certificado de su panel web caducó: " + ci.sujeto.take(60) + ". Indica un equipo sin mantenimiento.",
                    "Actualiza el firmware del equipo o sustitúyelo si ya no tiene soporte.", "Certificados"
                )
            } else if (ci.debil) {
                datos.hallazgo(
                    Riesgo.BAJO, "Certificado HTTPS débil en " + quien,
                    "Usa " + ci.algoritmo + (if (ci.bitsClave != null) " con clave de " + ci.bitsClave + " bits" else "") + ", un cifrado que ya no se considera seguro.",
                    "Actualiza el firmware del equipo o sustitúyelo si ya no tiene soporte.", "Certificados"
                )
            }
        }

        // ---- teléfono y modo avanzado
        if (op.forense) {
            progreso("Revisando el teléfono…")
            withContext(Dispatchers.IO) { TelefonoForense.analizar(app, datos, apps, indicadores) }
            if (salidaAdb != null) {
                val salida = salidaAdb
                withContext(Dispatchers.IO) { AnalisisAdb.analizar(app, datos, salida, red, apps, indicadores) }
            }
            if (indicadores.isNotEmpty()) cruzarIndicadores(datos, indicadores, red, lista, upnp)
        }

        // ---- cambios respecto a la visita anterior
        progreso("Comparando con la visita anterior…")
        val bssidAdb = salidaAdb?.let { ParserShell.wifiEstado(it["wifi"] ?: "")?.bssid }
        val idRed: String? = if (red.bssid != null || red.ssid != null) {
            red.idRed
        } else if (bssidAdb != null) {
            (gateway ?: "") + "|" + bssidAdb
        } else {
            null
        }
        if (idRed != null && gateway != null) {
            val ahora = LineaBase.Estado(
                macRouter = router?.mac,
                dns = red.dns,
                puertosRouter = router?.puertos?.map { it.def.puerto } ?: emptyList(),
                reenvios = upnp?.mapeos?.filter { it.activo }?.map { it.protocolo + " " + it.puertoExterno + "→" + it.clienteInterno + ":" + it.puertoInterno } ?: emptyList(),
                macs = lista.mapNotNull { it.mac },
                momento = System.currentTimeMillis()
            )
            val antes = LineaBase.cargar(app, idRed)
            if (antes != null) LineaBase.comparar(datos, antes, ahora)
            // La primera visita solo guarda. Si no se pudo ver nada nuevo del router, no se pisa lo anterior con datos vacíos.
            LineaBase.guardar(app, idRed, ahora)
        } else {
            datos.limitaciones.add("Sin el nombre ni el BSSID de la red (falta el permiso de ubicación o el modo avanzado) no se compara con visitas anteriores.")
        }

        progreso("Evaluando riesgos…")
        val informe = Analisis.evaluar(red, portal, router, lista, upnpRouter, datos.hallazgos)
        val momento = System.currentTimeMillis()
        val res = ResultadoAnalisis(red, portal, router, lista, upnpRouter, informe, completo, momento, datos)

        // ---- evidencia (y historial encadenado en el análisis forense)
        try {
            if (op.forense) {
                val previo = Libro.ultimoEnlace(app)
                val n = Libro.siguienteNumero(app)
                res.evidencia = Evidencia.contenido(app, res, n, previo)
                res.huellaEvidencia = Huellas.sha256(res.evidencia)
                Libro.agregar(app, n, momento, red.ssid ?: red.bssid ?: red.gateway ?: "?", informe.puntuacion, res.huellaEvidencia, previo)
            } else {
                res.evidencia = Evidencia.contenido(app, res, 0, "")
                res.huellaEvidencia = Huellas.sha256(res.evidencia)
            }
        } catch (e: Exception) {
            datos.limitaciones.add("No se pudo generar el paquete de evidencia: " + (e.message ?: e.javaClass.simpleName))
        }
        res
    }

    fun certificadoDe(d: Dispositivo): CertDispositivo.Info? {
        val p = d.puertos.firstOrNull { it.def.puerto == 443 } ?: d.puertos.firstOrNull { it.def.puerto == 8443 } ?: return null
        return CertDispositivo.leer(d.ip, p.def.puerto)
    }

    /** Compara con la lista de indicadores lo que no cubre ya el análisis del teléfono: DNS, IP del router y equipos de la red. */
    private fun cruzarIndicadores(datos: DatosForenses, indicadores: Set<String>, red: InfoRed, lista: List<Dispositivo>, upnp: UpnpAvanzado.Resultado?) {
        for (d in red.dns) {
            if (Indicadores.coincide(d, indicadores)) {
                datos.hallazgo(
                    Riesgo.CRITICO, "El DNS de la red figura en tus indicadores de compromiso: " + d,
                    "El servidor DNS " + d + " coincide con la lista que importaste: puede estar desviando tu tráfico.",
                    "No uses esta red. Conserva la evidencia firmada y avisa al administrador.", "IOC"
                )
            }
        }
        val ext = upnp?.ipExterna
        if (ext != null && Indicadores.coincide(ext, indicadores)) {
            datos.hallazgo(
                Riesgo.CRITICO, "La IP pública de la red figura en tus indicadores: " + ext,
                "La dirección pública de este router coincide con un indicador de compromiso.",
                "Conserva la evidencia firmada y avisa al operador.", "IOC"
            )
        }
        for (d in lista) {
            val coincide = Indicadores.coincide(d.ip, indicadores) || Indicadores.coincide(d.nombre, indicadores)
            if (coincide) {
                datos.hallazgo(
                    Riesgo.CRITICO, "Un equipo de la red figura en tus indicadores: " + d.nombreVisible + " (" + d.ip + ")",
                    "Su dirección o su nombre coinciden con la lista de indicadores que importaste.",
                    "Aíslalo de la red y conserva la evidencia firmada.", "IOC"
                )
            }
        }
    }
}
