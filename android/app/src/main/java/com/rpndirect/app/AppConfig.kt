package com.rpndirect.app

/**
 * Runtime config. The client now embeds the shared Go ICE engine (rpncore .aar):
 * it registers for a VPN IP, establishes the VpnService tun, and hands the tun fd
 * to the engine, which connects to the coordinator's WSS, negotiates an ICE path
 * to the assigned Pi exit, and tunnels WireGuard over it — direct when punchable,
 * TURN-relay only as last resort. The VPS is not in the data path on the direct
 * path. See core/ and global-puncher-requirement.
 */
object AppConfig {
    const val COORDINATOR_URL = "http://65.20.80.3:8089"
    const val WS_URL = "ws://65.20.80.3:8089/ws"
    const val DNS = "1.1.1.1"
    const val MTU = 1420

    /** Per-install access code. Phase-1 placeholder — set per device. */
    const val ACCESS_CODE = "REPLACE_WITH_ACCESS_CODE"
}
