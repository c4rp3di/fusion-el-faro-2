package com.vigia.faro.bt

import android.bluetooth.BluetoothClass

/** Un dispositivo Bluetooth visto durante el análisis (emparejado, BLE o clásico; puede ser varias cosas a la vez). */
class DispositivoBt(val direccion: String) {
    var nombre: String? = null
    var rssi: Int? = null
    var emparejado = false
    var esBle = false
    var esClasico = false
    var claseMayor: Int? = null
    var fabricanteId: Int? = null
    var conectable: Boolean? = null
    var txPower: Int? = null
    val uuids = LinkedHashSet<String>()

    /** Si por sus anuncios parece un rastreador (AirTag, SmartTag, Tile…): qué marca. */
    var rastreador: String? = null

    var alias: String? = null
    var confiable = false

    val nombreVisible: String
        get() = alias ?: nombre ?: Fabricantes.nombre(fabricanteId)?.let { "Dispositivo " + it } ?: "Sin nombre"

    val tipoRadio: String
        get() = when {
            esBle && esClasico -> "Dual (BLE y clásico)"
            esBle -> "BLE"
            esClasico -> "Clásico"
            emparejado -> "Emparejado"
            else -> "?"
        }

    val icono: String
        get() = when {
            rastreador != null -> "📍"
            claseMayor == BluetoothClass.Device.Major.AUDIO_VIDEO -> "🎧"
            claseMayor == BluetoothClass.Device.Major.COMPUTER -> "💻"
            claseMayor == BluetoothClass.Device.Major.PHONE -> "📱"
            claseMayor == BluetoothClass.Device.Major.PERIPHERAL -> "⌨"
            claseMayor == BluetoothClass.Device.Major.IMAGING -> "🖨"
            claseMayor == BluetoothClass.Device.Major.WEARABLE -> "⌚"
            claseMayor == BluetoothClass.Device.Major.HEALTH -> "❤"
            claseMayor == BluetoothClass.Device.Major.NETWORKING -> "📡"
            claseMayor == BluetoothClass.Device.Major.TOY -> "🧸"
            else -> "🔹"
        }

    val clase: String?
        get() = when (claseMayor) {
            BluetoothClass.Device.Major.AUDIO_VIDEO -> "Audio / vídeo"
            BluetoothClass.Device.Major.COMPUTER -> "Ordenador"
            BluetoothClass.Device.Major.PHONE -> "Teléfono"
            BluetoothClass.Device.Major.PERIPHERAL -> "Periférico (teclado, ratón…)"
            BluetoothClass.Device.Major.IMAGING -> "Impresora o cámara"
            BluetoothClass.Device.Major.WEARABLE -> "Dispositivo ponible"
            BluetoothClass.Device.Major.HEALTH -> "Salud"
            BluetoothClass.Device.Major.NETWORKING -> "Red"
            BluetoothClass.Device.Major.TOY -> "Juguete"
            else -> null
        }

    /** Distancia aproximada según la potencia recibida (muy variable: paredes, orientación y potencia de cada aparato). */
    val cercania: String?
        get() {
            val r = rssi ?: return null
            return when {
                r >= -60 -> "muy cerca"
                r >= -75 -> "cerca"
                r >= -90 -> "a media distancia"
                else -> "lejos"
            }
        }
}

class ResultadoBt(
    val dispositivos: List<DispositivoBt>,
    val sinBluetooth: Boolean,
    val apagado: Boolean,
    val faltanPermisos: Boolean,
    val nombreTelefono: String?,
    val visible: Boolean?,
    val momento: Long
)

/** Fabricantes por «company identifier» de Bluetooth SIG (lista parcial, solo los más habituales). */
object Fabricantes {
    private val TABLA = mapOf(
        0x0002 to "Intel", 0x0006 to "Microsoft", 0x000D to "Texas Instruments", 0x000F to "Broadcom", 0x004C to "Apple",
        0x0059 to "Nordic Semiconductor", 0x0075 to "Samsung", 0x0087 to "Garmin", 0x009E to "Bose", 0x00E0 to "Google",
        0x012D to "Sony", 0x0157 to "Huami (Amazfit/Zepp)", 0x0171 to "Amazon", 0x01DA to "Logitech", 0x02E5 to "Espressif",
        0x038F to "Xiaomi"
    )

    fun nombre(id: Int?): String? = if (id == null) null else TABLA[id]
}
