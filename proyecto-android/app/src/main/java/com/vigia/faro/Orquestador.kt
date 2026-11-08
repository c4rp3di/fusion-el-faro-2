package com.vigia.faro

import android.content.Context
import com.vigia.core.red.UtilRed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

class ResultadoAnalisis(
    val red: InfoRed,
    val portal: ResultadoPortal,
    val router: Dispositivo?,
    val dispositivos: List<Dispositivo>,
    val upnpRouter: Boolean,
    val informe: Informe,
    val completo: Boolean,
    val momento: Long
)

/** Ejecuta el análisis completo por fases y devuelve el informe. Se puede cancelar en cualquier momento. */
object Orquestador {

    private fun ipOrden(ip: String): Long = (UtilRed.parseIpv4(ip) ?: 0).toLong() and 0xFFFFFFFFL

    private fun esInfraestructura(r: RespuestaSsdp): Boolean {
        return r.st.contains("InternetGatewayDevice") || r.usn.contains("InternetGatewayDevice") || r.st.contains("WANIPConnection")
    }

    suspend fun analizar(c: Context, red: InfoRed, completo: Boolean, progreso: (String) -> Unit): ResultadoAnalisis = coroutineScope {
        val app = c.applicationContext
        val gateway = red.gateway

        progreso("Comprobando si la red tiene portal cautivo…")
        val portal = if (red.esWifi) Portal.comprobar() else ResultadoPortal(EstadoPortal.NO_COMPROBADO, "No es una red Wi-Fi.")

        // UPnP y mDNS escuchan mientras se hace el resto.
        val ssdpTarea = async { Descubridor.ssdp(app, 3500L) }
        val mdnsTarea = if (completo) async { Descubridor.mdns(app, 7000L) } else null

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
        if (router != null && gateway != null) {
            val rr = ssdp.firstOrNull { it.ip == gateway && it.ubicacion.isNotEmpty() }
            if (rr != null) {
                val desc = withContext(Dispatchers.IO) { Descubridor.descripcionUpnp(rr.ubicacion, gateway) }
                if (desc != null) {
                    router.nombre = router.nombre ?: desc.nombre
                    router.fabricante = desc.fabricante
                    router.modelo = desc.modelo
                }
            }
        }

        // ---- el resto de la red
        val lista = ArrayList<Dispositivo>()
        if (completo && red.ipLocal != null) {
            progreso("Buscando dispositivos…")
            val ips = Descubridor.rango(red.ipLocal, red.prefijo)
            val vivos = Descubridor.barrido(ips) { hechos, total -> progreso("Buscando dispositivos… " + hechos + "/" + total) }
            val vecinos = Descubridor.vecinos()
            val todos = HashSet<String>(vivos)
            for ((ip, _) in vecinos) if (ips.contains(ip)) todos.add(ip)
            for (r in ssdp) if (ips.contains(r.ip)) todos.add(r.ip)
            val servicios = mdnsTarea?.await() ?: emptyList()
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
                        val n = synchronized(pendientes) {
                            terminados++
                            terminados
                        }
                        progreso("Analizando dispositivos… " + n + "/" + pendientes.size)
                    }
                }
            }.awaitAll()
        } else if (red.ipLocal != null && router != null) {
            router.mac = Descubridor.vecinos()[router.ip]
            lista.add(router)
        }

        for (d in lista) Descubridor.clasificar(d)
        if (router != null && !lista.contains(router)) {
            Descubridor.clasificar(router)
        }

        // ---- dispositivos nuevos respecto a la última visita
        if (completo) {
            val previos = Conocidos.cargar(app, red.idRed)
            val actuales = ArrayList<String>()
            for (d in lista) {
                val id = d.mac ?: d.nombre
                if (id != null) {
                    actuales.add(id)
                    if (previos != null && !previos.contains(id) && !d.esEsteTelefono && !d.esRouter) d.nuevo = true
                }
            }
            Conocidos.guardar(app, red.idRed, actuales)
        }

        progreso("Evaluando riesgos…")
        val informe = Analisis.evaluar(red, portal, router, lista, upnpRouter)
        ResultadoAnalisis(red, portal, router, lista, upnpRouter, informe, completo, System.currentTimeMillis())
    }
}
