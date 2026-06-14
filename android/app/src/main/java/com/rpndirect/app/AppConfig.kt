package com.rpndirect.app

/**
 * Runtime configuration for the direct-path client.
 *
 * The client no longer ships a static WireGuard config. It:
 *   1. Generates/loads its own WG keypair on device.
 *   2. Discovers its public (NAT-mapped) endpoint via STUN, from the *same* UDP
 *      port WireGuard will bind — so the mapping it reports is the one WG reuses.
 *   3. Registers with the coordinator (access code + pubkey + endpoint) and gets
 *      back the assigned Pi's pubkey + live endpoint + the customer's VPN /32.
 *   4. Brings up a WireGuard tunnel that dials the Pi DIRECTLY — the VPS is only
 *      involved in signaling, never in the data path.
 *
 * Direct works because the Pi's Airtel CGNAT is endpoint-independent (cone): once
 * both sides send to each other's mapped endpoints, the port-restricted filter
 * opens and WireGuard's own keepalives hold the path. See airtel-nat-punchable.
 */
object AppConfig {
    const val TUNNEL_NAME = "rpndirect"

    const val COORDINATOR_URL = "http://65.20.80.3:8089"
    const val STUN_HOST = "65.20.80.3"
    const val STUN_PORT = 3479

    /**
     * Fixed WireGuard listen port. STUN is queried from this exact port so the
     * reflexive mapping we report to the coordinator matches the one WireGuard
     * will reuse when it rebinds the port (endpoint-independent NAT keeps it).
     */
    const val WG_LISTEN_PORT = 51820

    const val DNS = "1.1.1.1"

    /**
     * Per-install access code. Phase-1 placeholder — replace per device, or wire
     * a first-run entry screen that stores it in SharedPreferences.
     */
    const val ACCESS_CODE = "REPLACE_WITH_ACCESS_CODE"
}
