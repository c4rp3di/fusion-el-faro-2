package com.vigia.faro.forense

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/** NAT-PMP / PCP (UDP 5351): una sola consulta de lectura («¿cuál es tu IP externa?») para saber si el router abre puertos a petición. */
object NatPmp {

    class Respuesta(val ipExterna: String)

    /** Lee la respuesta de 12 bytes a una consulta de dirección externa. Devuelve null si no es válida o el router dio error. */
    fun leer(d: ByteArray, n: Int): Respuesta? {
        if (n < 12) return null
        if ((d[0].toInt() and 0xFF) != 0) return null
        if ((d[1].toInt() and 0xFF) != 128) return null
        val resultado = ((d[2].toInt() and 0xFF) shl 8) or (d[3].toInt() and 0xFF)
        if (resultado != 0) return null
        return Respuesta((d[8].toInt() and 0xFF).toString() + "." + (d[9].toInt() and 0xFF) + "." + (d[10].toInt() and 0xFF) + "." + (d[11].toInt() and 0xFF))
    }

    fun consultar(router: String): Respuesta? {
        val s = DatagramSocket()
        return try {
            s.soTimeout = 1200
            val q = byteArrayOf(0, 0)
            s.send(DatagramPacket(q, q.size, InetAddress.getByName(router), 5351))
            val buf = ByteArray(64)
            val p = DatagramPacket(buf, buf.size)
            s.receive(p)
            leer(buf, p.length)
        } catch (e: Exception) {
            null
        } finally {
            s.close()
        }
    }
}
