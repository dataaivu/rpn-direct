package com.rpndirect.app

import android.content.Context
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair

/** Generates a WireGuard keypair on first run and persists the private key. */
object Keys {
    private const val PREFS = "rpn_keys"
    private const val K_PRIV = "priv"

    fun load(ctx: Context): KeyPair {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val existing = p.getString(K_PRIV, null)
        if (existing != null) {
            return KeyPair(Key.fromBase64(existing))
        }
        val kp = KeyPair()
        p.edit().putString(K_PRIV, kp.privateKey.toBase64()).apply()
        return kp
    }
}
