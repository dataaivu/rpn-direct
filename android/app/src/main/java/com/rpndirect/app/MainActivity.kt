package com.rpndirect.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.BufferedReader
import java.io.StringReader
import kotlin.concurrent.thread

/**
 * Minimal from-scratch client: one Connect/Disconnect button that brings a plain
 * WireGuard tunnel to the VPS up and down. No Tailscale, no account, no UI framework.
 */
class MainActivity : Activity() {

    private lateinit var backend: Backend
    private lateinit var statusView: TextView
    private lateinit var toggleBtn: Button
    private val tunnel = RpnTunnel()

    /** Tunnel handle the backend tracks; reports state changes back to the UI. */
    private inner class RpnTunnel : Tunnel {
        override fun getName(): String = AppConfig.TUNNEL_NAME
        override fun onStateChange(newState: Tunnel.State) {
            runOnUiThread { render(newState) }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        statusView = findViewById(R.id.status)
        toggleBtn = findViewById(R.id.toggle)
        backend = GoBackend(applicationContext)
        toggleBtn.setOnClickListener { onToggle() }
        toggleBtn.requestFocus()
        render(currentState())
    }

    private fun currentState(): Tunnel.State =
        try { backend.getState(tunnel) } catch (e: Exception) { Tunnel.State.DOWN }

    private fun onToggle() {
        val target =
            if (currentState() == Tunnel.State.UP) Tunnel.State.DOWN else Tunnel.State.UP

        // Bringing the tunnel up needs the one-time VPN consent dialog.
        if (target == Tunnel.State.UP) {
            val prepare = VpnService.prepare(this)
            if (prepare != null) {
                startActivityForResult(prepare, REQ_VPN)
                return
            }
        }
        applyState(target)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) applyState(Tunnel.State.UP)
            else statusView.text = getString(R.string.status_denied)
        }
    }

    private fun applyState(target: Tunnel.State) {
        statusView.text = getString(R.string.status_working)
        toggleBtn.isEnabled = false
        thread {
            try {
                val cfg = Config.parse(BufferedReader(StringReader(AppConfig.WG_CONFIG)))
                backend.setState(tunnel, target, cfg)
                val now = backend.getState(tunnel)
                runOnUiThread {
                    render(now)
                    toggleBtn.isEnabled = true
                }
            } catch (e: Exception) {
                runOnUiThread {
                    statusView.text = getString(R.string.status_error, e.message ?: "unknown")
                    toggleBtn.isEnabled = true
                }
            }
        }
    }

    private fun render(state: Tunnel.State) {
        val up = state == Tunnel.State.UP
        statusView.text =
            getString(if (up) R.string.status_connected else R.string.status_disconnected)
        toggleBtn.text =
            getString(if (up) R.string.btn_disconnect else R.string.btn_connect)
    }

    private companion object {
        const val REQ_VPN = 1001
    }
}
