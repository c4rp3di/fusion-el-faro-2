package com.vigia.faro.bt

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import com.vigia.faro.Alias
import kotlinx.coroutines.delay
import java.util.UUID

/** Busca los dispositivos Bluetooth de alrededor (BLE y clásico) y los ya emparejados. Solo escucha: no se conecta a ninguno. */
object ScannerBt {

    /** Android exige el permiso de ubicación para escanear Bluetooth; El Faro no calcula ni guarda la posición. */
    fun permisos(): Array<String> {
        return if (Build.VERSION.SDK_INT >= 31) {
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.ACCESS_FINE_LOCATION)
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    fun tienePermisos(c: Context): Boolean =
        permisos().all { ContextCompat.checkSelfPermission(c, it) == PackageManager.PERMISSION_GRANTED }

    private fun corto(u: UUID): String {
        val s = u.toString().lowercase()
        return if (s.startsWith("0000") && s.endsWith("-0000-1000-8000-00805f9b34fb")) s.substring(4, 8) else s
    }

    @SuppressLint("MissingPermission")
    private fun nombreSeguro(d: BluetoothDevice): String? {
        return try {
            d.name
        } catch (e: SecurityException) {
            null
        }
    }

    @SuppressLint("MissingPermission")
    private fun claseSegura(d: BluetoothDevice): Int? {
        return try {
            d.bluetoothClass?.majorDeviceClass
        } catch (e: SecurityException) {
            null
        }
    }

    private fun detectarRastreador(x: DispositivoBt) {
        if (x.rastreador != null) return
        x.rastreador = when {
            x.uuids.contains("feed") || x.uuids.contains("feec") -> "Tile"
            x.uuids.contains("fd5a") -> "Samsung SmartTag"
            else -> null
        }
    }

    private fun registrarBle(x: DispositivoBt, r: ScanResult) {
        x.esBle = true
        x.rssi = maxOf(x.rssi ?: -127, r.rssi)
        val rec = r.scanRecord
        val n = rec?.deviceName
        if (n != null && n.isNotEmpty()) x.nombre = n
        if (x.nombre == null) x.nombre = nombreSeguro(r.device)
        if (Build.VERSION.SDK_INT >= 26) x.conectable = r.isConnectable
        if (rec != null) {
            val man = rec.manufacturerSpecificData
            if (man != null) {
                for (i in 0 until man.size()) {
                    val id = man.keyAt(i)
                    val bytes: ByteArray? = man.valueAt(i)
                    x.fabricanteId = id
                    // Mensaje «Buscar» de Apple (tipo 0x12, longitud 0x19): lo emiten los AirTag, pero también AirPods y iPhones.
                    if (id == 0x004C && bytes != null && bytes.size >= 2 && (bytes[0].toInt() and 0xFF) == 0x12 && (bytes[1].toInt() and 0xFF) == 0x19) {
                        x.rastreador = "Apple Buscar (AirTag, AirPods o un iPhone)"
                    }
                }
            }
            rec.serviceUuids?.forEach { x.uuids.add(corto(it.uuid)) }
            rec.serviceData?.keys?.forEach { x.uuids.add(corto(it.uuid)) }
            if (rec.txPowerLevel != Int.MIN_VALUE) x.txPower = rec.txPowerLevel
        }
        detectarRastreador(x)
    }

    @Suppress("DEPRECATION")
    private fun dispositivoDe(i: Intent): BluetoothDevice? {
        return if (Build.VERSION.SDK_INT >= 33) {
            i.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
        } else {
            i.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE)
        }
    }

    @SuppressLint("MissingPermission")
    suspend fun escanear(c: Context, progreso: (String) -> Unit): ResultadoBt {
        val app = c.applicationContext
        val ahora = System.currentTimeMillis()
        val adapter = app.getSystemService(BluetoothManager::class.java)?.adapter
            ?: return ResultadoBt(emptyList(), true, false, false, null, null, ahora)
        if (!tienePermisos(app)) return ResultadoBt(emptyList(), false, false, true, null, null, ahora)
        if (!adapter.isEnabled) return ResultadoBt(emptyList(), false, true, false, null, null, ahora)

        val mapa = LinkedHashMap<String, DispositivoBt>()
        val cerrojo = Any()
        fun obtener(dir: String): DispositivoBt = mapa.getOrPut(dir) { DispositivoBt(dir) }

        val nombreTelefono = try {
            adapter.name
        } catch (e: SecurityException) {
            null
        }
        val visible = try {
            adapter.scanMode == BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE
        } catch (e: SecurityException) {
            null
        }

        try {
            for (d in adapter.bondedDevices) {
                synchronized(cerrojo) {
                    val x = obtener(d.address)
                    x.emparejado = true
                    if (x.nombre == null) x.nombre = nombreSeguro(d)
                    x.claseMayor = claseSegura(d)
                    when (d.type) {
                        BluetoothDevice.DEVICE_TYPE_LE -> x.esBle = true
                        BluetoothDevice.DEVICE_TYPE_CLASSIC -> x.esClasico = true
                        BluetoothDevice.DEVICE_TYPE_DUAL -> {
                            x.esBle = true
                            x.esClasico = true
                        }
                        else -> {}
                    }
                    Unit
                }
            }
        } catch (e: SecurityException) {
        }

        val le = adapter.bluetoothLeScanner
        if (le != null) {
            progreso("Buscando dispositivos Bluetooth de bajo consumo (9 s)…")
            val cb = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    synchronized(cerrojo) { registrarBle(obtener(result.device.address), result) }
                }

                override fun onBatchScanResults(results: MutableList<ScanResult>) {
                    for (r in results) onScanResult(0, r)
                }
            }
            try {
                le.startScan(null, ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), cb)
                delay(9000L)
            } catch (e: Exception) {
            } finally {
                try {
                    le.stopScan(cb)
                } catch (e: Exception) {
                }
            }
        }

        progreso("Buscando dispositivos Bluetooth clásicos (10 s)…")
        val receptor = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != BluetoothDevice.ACTION_FOUND) return
                val d = dispositivoDe(intent) ?: return
                val rssi = intent.getShortExtra(BluetoothDevice.EXTRA_RSSI, Short.MIN_VALUE).toInt()
                synchronized(cerrojo) {
                    val x = obtener(d.address)
                    x.esClasico = true
                    if (rssi != Short.MIN_VALUE.toInt()) x.rssi = maxOf(x.rssi ?: -127, rssi)
                    if (x.nombre == null) x.nombre = nombreSeguro(d)
                    if (x.claseMayor == null) x.claseMayor = claseSegura(d)
                    Unit
                }
            }
        }
        try {
            app.registerReceiver(receptor, IntentFilter(BluetoothDevice.ACTION_FOUND))
            adapter.startDiscovery()
            delay(10000L)
        } catch (e: Exception) {
        } finally {
            try {
                adapter.cancelDiscovery()
            } catch (e: Exception) {
            }
            try {
                app.unregisterReceiver(receptor)
            } catch (e: Exception) {
            }
        }

        val lista = synchronized(cerrojo) { ArrayList(mapa.values) }
        for (x in lista) {
            val a = Alias.obtenerBt(app, x.direccion)
            if (a != null) {
                x.alias = a.nombre
                x.confiable = a.confiable
            }
        }
        lista.sortWith(compareByDescending<DispositivoBt> { it.rastreador != null }.thenByDescending { it.rssi ?: -200 })
        return ResultadoBt(lista, false, false, false, nombreTelefono, visible, ahora)
    }
}
