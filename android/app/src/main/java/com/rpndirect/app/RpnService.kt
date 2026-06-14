package com.rpndirect.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.crypto.KeyPair
import java.io.BufferedReader
import java.io.StringReader
import java.net.DatagramSocket
import java.net.InetSocketAddress
import kotlin.concurrent.thread

/**
 * Foreground service that owns the WireGuard backend and the whole connect
 * lifecycle. Living in a foreground service (not the Activity) is what fixes the
 * lifecycle failures the test suite caught:
 *   - foreground notification keeps the process alive across screen-off / doze (T6)
 *   - a PARTIAL_WAKE_LOCK stops the CPU freezing the wireguard-go goroutines
 *   - backend ownership outlives the Activity, so reconnect works after the UI is
 *     destroyed or force-stopped (T8/T9)
 *
 * Connect flow: STUN (from the fixed WG port) -> register with coordinator ->
 * build a config that dials the assigned Pi directly -> setState(UP).
 */
class RpnService : Service() {

    inner class LocalBinder : Binder() {
        val service get() = this@RpnService
    }
    private val binder = LocalBinder()

    private lateinit var backend: Backend
    private lateinit var wakeLock: PowerManager.WakeLock
    private val tunnel = RpnTunnel()

    @Volatile var lastError: String? = null; private set
    @Volatile var connecting = false; private set

    /** UI observer; set by the bound Activity. */
    var onState: ((Tunnel.State) -> Unit)? = null

    private inner class RpnTunnel : Tunnel {
        override fun getName() = AppConfig.TUNNEL_NAME
        override fun onStateChange(newState: Tunnel.State) {
            onState?.invoke(newState)
            if (newState == Tunnel.State.DOWN) releaseAndStop()
        }
    }

    override fun onCreate() {
        super.onCreate()
        backend = GoBackend(applicationContext)
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "rpn:tunnel").apply {
            setReferenceCounted(false)
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    fun state(): Tunnel.State =
        try { backend.getState(tunnel) } catch (e: Exception) { Tunnel.State.DOWN }

    /** Brings the tunnel up. Safe to call repeatedly; ignores while already connecting. */
    fun connect() {
        if (connecting || state() == Tunnel.State.UP) return
        connecting = true
        lastError = null
        startForegroundCompat()
        if (!wakeLock.isHeld) wakeLock.acquire()
        onState?.invoke(state())

        thread(name = "rpn-connect") {
            try {
                val keys = Keys.load(this)
                val endpoint = discoverEndpoint()
                    ?: throw RuntimeException("STUN failed — no public endpoint")
                val pi = Coordinator.register(
                    AppConfig.COORDINATOR_URL,
                    AppConfig.ACCESS_CODE,
                    keys.publicKey.toBase64(),
                    endpoint,
                )
                Log.i(TAG, "registered: pi=${pi.piEndpoint} vpn=${pi.vpnIp} self=$endpoint")
                backend.setState(tunnel, Tunnel.State.UP, buildConfig(keys, pi))
            } catch (e: Exception) {
                Log.e(TAG, "connect failed", e)
                lastError = e.message ?: "unknown error"
                try { backend.setState(tunnel, Tunnel.State.DOWN, null) } catch (_: Exception) {}
                releaseAndStop()
            } finally {
                connecting = false
                onState?.invoke(state())
            }
        }
    }

    fun disconnect() {
        thread(name = "rpn-disconnect") {
            try {
                backend.setState(tunnel, Tunnel.State.DOWN, null)
            } catch (e: Exception) {
                Log.e(TAG, "disconnect failed", e)
            } finally {
                releaseAndStop()
                onState?.invoke(state())
            }
        }
    }

    /**
     * Bind the exact port WireGuard will use, query STUN, then close so GoBackend
     * can rebind it. Endpoint-independent (cone) NAT keeps the mapping alive across
     * the brief close, so the reported endpoint stays valid for WireGuard.
     */
    private fun discoverEndpoint(): String? = try {
        DatagramSocket(null).use { s ->
            s.reuseAddress = true
            s.bind(InetSocketAddress(AppConfig.WG_LISTEN_PORT))
            Stun.reflexive(s, InetSocketAddress(AppConfig.STUN_HOST, AppConfig.STUN_PORT))
        }
    } catch (e: Exception) {
        Log.e(TAG, "STUN error", e); null
    }

    private fun buildConfig(keys: KeyPair, pi: PiConfig): Config {
        val text = """
            [Interface]
            PrivateKey = ${keys.privateKey.toBase64()}
            Address = ${pi.vpnIp}
            DNS = ${AppConfig.DNS}
            ListenPort = ${AppConfig.WG_LISTEN_PORT}

            [Peer]
            PublicKey = ${pi.piPubKey}
            Endpoint = ${pi.piEndpoint}
            AllowedIPs = 0.0.0.0/0
            PersistentKeepalive = 5
        """.trimIndent()
        return Config.parse(BufferedReader(StringReader(text)))
    }

    // ── foreground / wakelock plumbing ──────────────────────────────────────────

    private fun startForegroundCompat() {
        startForeground(NOTIF_ID, buildNotification())
    }

    private fun releaseAndStop() {
        if (wakeLock.isHeld) wakeLock.release()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            stopForeground(STOP_FOREGROUND_REMOVE)
        else @Suppress("DEPRECATION") stopForeground(true)
    }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW)
                )
            }
        }
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, CHANNEL)
        else
            @Suppress("DEPRECATION") Notification.Builder(this)
        return b.setContentTitle("RPN Direct")
            .setContentText("Tunnel active")
            .setSmallIcon(android.R.drawable.stat_sys_vpn_ind)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        if (wakeLock.isHeld) wakeLock.release()
        super.onDestroy()
    }

    private companion object {
        const val TAG = "RpnService"
        const val NOTIF_ID = 1
        const val CHANNEL = "rpn_vpn"
    }
}
