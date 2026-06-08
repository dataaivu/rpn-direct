package com.rpndirect.app

/**
 * Phase-1 tunnel config for the Fire TV Cube test device.
 *
 * NOTE: this is a TEST key issued by server/setup-wgd0.sh against the isolated wgd0
 * interface on the VPS. The repo is private; rotate this key before any real use.
 * Exit at this phase = the VPS's own IP. The Pi residential exit is wired in later.
 */
object AppConfig {
    const val TUNNEL_NAME = "rpndirect"

    val WG_CONFIG = """
        [Interface]
        PrivateKey = MN0XRqTuVRcrzHBU+ZxUWh/Xqf/FFs3XprqK2+eKq0M=
        Address = 10.99.0.101/32
        DNS = 1.1.1.1

        [Peer]
        PublicKey = UvEK1hM6jkX1D0ngwkYdB/QlURB4nekJj/Rq01w/Glg=
        Endpoint = 65.20.80.3:51820
        AllowedIPs = 0.0.0.0/0
        PersistentKeepalive = 25
    """.trimIndent()
}
