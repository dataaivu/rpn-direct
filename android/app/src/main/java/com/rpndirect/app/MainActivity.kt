package com.rpndirect.app

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Bundle
import android.os.IBinder
import android.widget.Button
import android.widget.TextView
import com.wireguard.android.backend.Tunnel

/**
 * Thin UI. All tunnel state lives in [RpnService] (a foreground service), which
 * outlives this Activity — so connect/disconnect survive the UI being destroyed.
 */
class MainActivity : Activity() {

    private var svc: RpnService? = null
    private lateinit var status: TextView
    private lateinit var toggle: Button
    private var pendingConnect = false

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, b: IBinder?) {
            svc = (b as RpnService.LocalBinder).service
            svc?.onState = { s -> runOnUiThread { render(s) } }
            render(svc?.state() ?: Tunnel.State.DOWN)
            if (pendingConnect) { pendingConnect = false; svc?.connect() }
        }
        override fun onServiceDisconnected(name: ComponentName?) { svc = null }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        toggle = findViewById(R.id.toggle)
        toggle.setOnClickListener { onToggle() }
        toggle.requestFocus()
    }

    override fun onStart() {
        super.onStart()
        val i = Intent(this, RpnService::class.java)
        startService(i)
        bindService(i, conn, Context.BIND_AUTO_CREATE)
    }

    override fun onStop() {
        super.onStop()
        svc?.onState = null
        try { unbindService(conn) } catch (_: Exception) {}
    }

    private fun onToggle() {
        val s = svc ?: return
        if (s.state() == Tunnel.State.UP) { s.disconnect(); return }
        // Bringing the tunnel up needs the one-time VPN consent dialog.
        val prepare = VpnService.prepare(this)
        if (prepare != null) startActivityForResult(prepare, REQ_VPN) else s.connect()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                if (svc != null) svc?.connect() else pendingConnect = true
            } else {
                status.text = getString(R.string.status_denied)
            }
        }
    }

    private fun render(state: Tunnel.State) {
        val up = state == Tunnel.State.UP
        val err = svc?.lastError
        status.text = when {
            svc?.connecting == true -> getString(R.string.status_working)
            !up && err != null -> getString(R.string.status_error, err)
            up -> getString(R.string.status_connected)
            else -> getString(R.string.status_disconnected)
        }
        toggle.text = getString(if (up) R.string.btn_disconnect else R.string.btn_connect)
        toggle.isEnabled = svc?.connecting != true
    }

    private companion object { const val REQ_VPN = 1001 }
}
