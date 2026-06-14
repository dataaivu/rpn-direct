package com.rpndirect.app

import android.content.Context
import android.util.Base64
import java.security.SecureRandom

/**
 * Generates a WireGuard private key on first run and persists it. No WireGuard
 * crypto library needed — the public key is derived by the Go engine
 * (Mobile.publicKey). The 32 random bytes are clamped per Curve25519/WireGuard.
 */
object Keys {
    private const val PREFS = "rpn_keys"
    private const val K_PRIV = "priv"

    fun privateKeyB64(ctx: Context): String {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        p.getString(K_PRIV, null)?.let { return it }
        val k = ByteArray(32)
        SecureRandom().nextBytes(k)
        k[0] = (k[0].toInt() and 248).toByte()
        k[31] = ((k[31].toInt() and 127) or 64).toByte()
        val b64 = Base64.encodeToString(k, Base64.NO_WRAP)
        p.edit().putString(K_PRIV, b64).apply()
        return b64
    }
}
