package com.rpndirect.app

import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/** The Pi this device was assigned, as returned by the coordinator. */
data class PiConfig(
    val piPubKey: String,
    val piEndpoint: String,
    val vpnIp: String,
)

object Coordinator {

    /**
     * Registers this device and returns the assigned Pi. Sends our STUN-reflexive
     * [endpoint] so the Pi can punch back toward us (opens its port-restricted
     * filter). Talks to POST /customer/register.
     */
    fun register(baseUrl: String, accessCode: String, pubKey: String, endpoint: String): PiConfig {
        val body = JSONObject()
            .put("access_code", accessCode)
            .put("pubkey", pubKey)
            .put("endpoint", endpoint)
            .toString()

        val conn = (URL("$baseUrl/customer/register").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 10_000
            readTimeout = 10_000
            setRequestProperty("Content-Type", "application/json")
        }
        OutputStreamWriter(conn.outputStream).use { it.write(body) }

        val code = conn.responseCode
        if (code != 200) {
            val err = conn.errorStream?.bufferedReader()?.readText()?.trim() ?: ""
            throw RuntimeException("register failed ($code): $err")
        }
        val json = JSONObject(conn.inputStream.bufferedReader().readText())
        val vpn = json.getString("vpn_ip")
        return PiConfig(
            piPubKey = json.getString("pi_pubkey"),
            piEndpoint = json.getString("pi_endpoint"),
            // coordinator returns "10.100.x.y/32"; ensure a /32 for the Interface Address.
            vpnIp = if (vpn.contains("/")) vpn else "$vpn/32",
        )
    }
}
