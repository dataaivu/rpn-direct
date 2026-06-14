package com.rpndirect.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import mobile.Mobile
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * The VpnService + foreground service that owns the tunnel. Flow on connect:
 *   1. load/derive WG keys (pubkey via the engine, no crypto lib)
 *   2. REST-register for a VPN /32
 *   3. establish() the tun — and exclude THIS app from the tunnel so the engine's
 *      own ICE/WireGuard UDP sockets ride the real network (no routing loop)
 *   4. hand the tun fd to the Go ICE engine (Mobile.start)
 *
 * Foreground + wakelock keep the process alive across screen-off/doze; the engine
 * lives in the service so it survives Activity teardown.
 */
class RpnService : VpnService() {

    inner class LocalBinder : Binder() {
        val service get() = this@RpnService
    }
    private val binder = LocalBinder()

    private var tunFd: Int = -1
    private lateinit var wakeLock: PowerManager.WakeLock

    @Volatile var lastError: String? = null; private set
    @Volatile var connecting = false; private set
    @Volatile var connected = false; private set

    var onState: (() -> Unit)? = null

    override fun onCreate() {
        super.onCreate()
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "rpn:tunnel").apply {
            setReferenceCounted(false)
        }
    }

    // The system binds with SERVICE_INTERFACE for the VPN; our UI binds otherwise.
    override fun onBind(intent: Intent?): IBinder? {
        if (intent?.action == SERVICE_INTERFACE) return super.onBind(intent)
        return binder
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    fun connect() {
        if (connecting || connected) return
        connecting = true
        lastError = null
        startForegroundCompat()
        if (!wakeLock.isHeld) wakeLock.acquire()
        notifyState()

        thread(name = "rpn-connect") {
            try {
                val priv = Keys.privateKeyB64(this)
                val pub = Mobile.publicKey(priv)
                if (pub.isNullOrEmpty()) throw RuntimeException("public key derivation failed")

                val vpnIp = Coordinator.registerVpnIp(AppConfig.COORDINATOR_URL, AppConfig.ACCESS_CODE, pub)

                val builder = Builder()
                    .addAddress(vpnIp.substringBefore("/"), 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(AppConfig.DNS)
                    .setMtu(AppConfig.MTU)
                    .setSession("RPN Direct")
                // Keep our own traffic (the engine's sockets) OFF the tunnel.
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (e: PackageManager.NameNotFoundException) {
                    Log.w(TAG, "could not exclude self from VPN", e)
                }

                val pfd = builder.establish() ?: throw RuntimeException("establish() returned null")
                tunFd = pfd.detachFd() // Go engine owns the fd from here

                val cfg = JSONObject()
                    .put("wsURL", AppConfig.WS_URL)
                    .put("accessCode", AppConfig.ACCESS_CODE)
                    .put("privateKey", priv)
                    .put("role", "client")
                    .put("name", "android")
                    .toString()

                val err = Mobile.start(cfg, tunFd.toLong())
                if (!err.isNullOrEmpty()) throw RuntimeException(err)
                connected = true
                Log.i(TAG, "engine started; status=${Mobile.status()}")
            } catch (e: Exception) {
                Log.e(TAG, "connect failed", e)
                lastError = e.message ?: "unknown error"
                cleanup()
            } finally {
                connecting = false
                notifyState()
            }
        }
    }

    fun disconnect() {
        thread(name = "rpn-disconnect") {
            try {
                Mobile.stop()
            } catch (e: Exception) {
                Log.e(TAG, "stop failed", e)
            }
            cleanup()
            notifyState()
        }
    }

    fun statusText(): String = try { Mobile.status() } catch (e: Exception) { "down" }

    private fun cleanup() {
        connected = false
        tunFd = -1
        if (wakeLock.isHeld) wakeLock.release()
        stopForegroundCompat()
    }

    private fun notifyState() = onState?.invoke()

    // ── foreground plumbing ─────────────────────────────────────────────────

    private fun startForegroundCompat() {
        startForeground(NOTIF_ID, buildNotification())
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
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
            .setSmallIcon(R.drawable.banner)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        try { Mobile.stop() } catch (_: Exception) {}
        if (wakeLock.isHeld) wakeLock.release()
        super.onDestroy()
    }

    private companion object {
        const val TAG = "RpnService"
        const val NOTIF_ID = 1
        const val CHANNEL = "rpn_vpn"
    }
}
