package com.rpndirect.app

import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

object Coordinator {

    /**
     * Registers the device (creates the customer record with our pubkey) and
     * returns the assigned VPN /32 used to configure the tun, e.g. "10.100.10.5/32".
     * The actual exit selection + path negotiation happens later over the engine's
     * WSS signaling — this REST call only allocates the address/identity.
     */
    fun registerVpnIp(baseUrl: String, accessCode: String, pubKey: String): String {
        val body = JSONObject()
            .put("access_code", accessCode)
            .put("pubkey", pubKey)
            .put("endpoint", "")
            .toString()
        val conn = (URL("$baseUrl/customer/register").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 10_000
            readTimeout = 10_000
            setRequestProperty("Content-Type", "application/json")
        }
        OutputStreamWriter(conn.outputStream).use { it.write(body) }
        if (conn.responseCode != 200) {
            val err = conn.errorStream?.bufferedReader()?.readText()?.trim() ?: ""
            throw RuntimeException("register failed (${conn.responseCode}): $err")
        }
        val json = JSONObject(conn.inputStream.bufferedReader().readText())
        val vpn = json.getString("vpn_ip")
        return if (vpn.contains("/")) vpn else "$vpn/32"
    }
}
