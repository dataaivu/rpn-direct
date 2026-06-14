package com.rpndirect.app

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom

/**
 * Minimal RFC 5389 STUN client: one Binding request, returns the server-reflexive
 * endpoint ("ip:port"). Query from the SAME local port WireGuard will bind, so the
 * mapping reported to the coordinator matches the one WireGuard reuses.
 */
object Stun {

    fun reflexive(socket: DatagramSocket, server: InetSocketAddress, timeoutMs: Int = 3000): String? {
        val txid = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val req = ByteArray(20)
        req[0] = 0x00; req[1] = 0x01           // Binding Request
        req[2] = 0x00; req[3] = 0x00           // length 0 (no attributes)
        req[4] = 0x21; req[5] = 0x12           // magic cookie 0x2112A442
        req[6] = 0xA4.toByte(); req[7] = 0x42
        System.arraycopy(txid, 0, req, 8, 12)

        socket.soTimeout = timeoutMs
        socket.send(DatagramPacket(req, req.size, server))

        val buf = ByteArray(512)
        val resp = DatagramPacket(buf, buf.size)
        return try {
            socket.receive(resp)
            parse(buf, resp.length)
        } catch (e: Exception) {
            null
        }
    }

    private fun parse(buf: ByteArray, len: Int): String? {
        if (len < 20) return null
        var pos = 20 // skip 20-byte STUN header
        while (pos + 4 <= len) {
            val type = ((buf[pos].toInt() and 0xFF) shl 8) or (buf[pos + 1].toInt() and 0xFF)
            val alen = ((buf[pos + 2].toInt() and 0xFF) shl 8) or (buf[pos + 3].toInt() and 0xFF)
            val v = pos + 4
            if (v + alen > len) break
            // 0x0020 XOR-MAPPED-ADDRESS (preferred), 0x0001 MAPPED-ADDRESS (legacy)
            if (type == 0x0020 || type == 0x0001) {
                val xor = type == 0x0020
                val family = buf[v + 1].toInt() and 0xFF
                if (family == 0x01) { // IPv4
                    var port = ((buf[v + 2].toInt() and 0xFF) shl 8) or (buf[v + 3].toInt() and 0xFF)
                    val ip = ByteArray(4) { buf[v + 4 + it] }
                    if (xor) {
                        port = port xor 0x2112
                        ip[0] = (ip[0].toInt() xor 0x21).toByte()
                        ip[1] = (ip[1].toInt() xor 0x12).toByte()
                        ip[2] = (ip[2].toInt() xor 0xA4).toByte()
                        ip[3] = (ip[3].toInt() xor 0x42).toByte()
                    }
                    val addr = InetAddress.getByAddress(ip).hostAddress
                    return "$addr:$port"
                }
            }
            // advance past value + 4-byte alignment padding
            pos = v + alen + ((4 - (alen % 4)) % 4)
        }
        return null
    }
}
