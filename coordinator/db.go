package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

// ── schema ────────────────────────────────────────────────────────────────────

const schema = `
CREATE TABLE IF NOT EXISTS pis (
    id         TEXT PRIMARY KEY,          -- Pi serial number
    pubkey     TEXT UNIQUE NOT NULL,      -- WireGuard public key
    vpn_ip     TEXT UNIQUE NOT NULL,      -- assigned VPN /32 (10.100.x.x)
    name       TEXT    DEFAULT '',
    location   TEXT    DEFAULT '',
    stun_ep    TEXT    DEFAULT '',        -- last known STUN public endpoint
    last_seen  INTEGER DEFAULT 0,         -- unix timestamp of last heartbeat
    customers  INTEGER DEFAULT 0,         -- active customer count (from heartbeat)
    active     INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS customers (
    id        TEXT PRIMARY KEY,           -- access code (stable identity)
    pubkey    TEXT,                        -- WireGuard public key (set on first connect)
    vpn_ip    TEXT UNIQUE NOT NULL,        -- assigned VPN /32 (10.100.y.y)
    pi_id     TEXT REFERENCES pis(id),    -- assigned Pi
    last_seen INTEGER DEFAULT 0,
    active    INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS access_codes (
    code      TEXT PRIMARY KEY,
    network   TEXT DEFAULT 'default',
    used_by   TEXT REFERENCES customers(id),
    created   INTEGER DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_pi_load     ON pis(active, last_seen DESC, customers ASC);
CREATE INDEX IF NOT EXISTS idx_cust_pi     ON customers(pi_id, active);
CREATE INDEX IF NOT EXISTS idx_code_used   ON access_codes(used_by);
`

// ── records ───────────────────────────────────────────────────────────────────

type PiRecord struct {
	ID        string
	PubKey    string
	VPNIP     string
	Name      string
	Location  string
	StunEP    string
	LastSeen  int64
	Customers int
	Active    int
}

type CustomerRecord struct {
	ID       string
	PubKey   string
	VPNIP    string
	PiID     string
	LastSeen int64
	Active   int
}

// ── db ────────────────────────────────────────────────────────────────────────

type store struct {
	db *sql.DB
}

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	log.Printf("db open: %s", path)
	return &store{db}, nil
}

// ── Pi operations ─────────────────────────────────────────────────────────────

func (s *store) piByID(id string) (*PiRecord, error) {
	var p PiRecord
	err := s.db.QueryRow(
		`SELECT id, pubkey, vpn_ip, name, location, stun_ep, last_seen, customers, active FROM pis WHERE id = ?`, id,
	).Scan(&p.ID, &p.PubKey, &p.VPNIP, &p.Name, &p.Location, &p.StunEP, &p.LastSeen, &p.Customers, &p.Active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func (s *store) piByPubKey(pubKey string) (*PiRecord, error) {
	var p PiRecord
	err := s.db.QueryRow(
		`SELECT id, pubkey, vpn_ip, name, location, stun_ep, last_seen, customers, active FROM pis WHERE pubkey = ?`, pubKey,
	).Scan(&p.ID, &p.PubKey, &p.VPNIP, &p.Name, &p.Location, &p.StunEP, &p.LastSeen, &p.Customers, &p.Active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func (s *store) upsertPi(id, pubKey, vpnIP, name, location string) error {
	_, err := s.db.Exec(`
		INSERT INTO pis(id, pubkey, vpn_ip, name, location)
		VALUES(?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			pubkey   = excluded.pubkey,
			name     = COALESCE(NULLIF(excluded.name,''), pis.name),
			location = COALESCE(NULLIF(excluded.location,''), pis.location)
	`, id, pubKey, vpnIP, name, location)
	return err
}

func (s *store) piHeartbeat(id, stunEP string, customers int) error {
	_, err := s.db.Exec(
		`UPDATE pis SET last_seen=strftime('%s','now'), stun_ep=?, customers=? WHERE id=?`,
		stunEP, customers, id,
	)
	return err
}

// leastLoadedPi returns the active Pi with fewest customers and a recent heartbeat.
func (s *store) leastLoadedPi() (*PiRecord, error) {
	var p PiRecord
	err := s.db.QueryRow(`
		SELECT id, pubkey, vpn_ip, name, location, stun_ep, last_seen, customers, active
		FROM pis
		WHERE active = 1
		  AND last_seen > strftime('%s','now') - 120
		  AND stun_ep != ''
		ORDER BY customers ASC, last_seen DESC
		LIMIT 1
	`).Scan(&p.ID, &p.PubKey, &p.VPNIP, &p.Name, &p.Location, &p.StunEP, &p.LastSeen, &p.Customers, &p.Active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func (s *store) listPis() ([]PiRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, pubkey, vpn_ip, name, location, stun_ep, last_seen, customers, active
		FROM pis ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PiRecord
	for rows.Next() {
		var p PiRecord
		if err := rows.Scan(&p.ID, &p.PubKey, &p.VPNIP, &p.Name, &p.Location, &p.StunEP, &p.LastSeen, &p.Customers, &p.Active); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── customer operations ───────────────────────────────────────────────────────

func (s *store) customerByID(id string) (*CustomerRecord, error) {
	var c CustomerRecord
	err := s.db.QueryRow(
		`SELECT id, COALESCE(pubkey,''), vpn_ip, COALESCE(pi_id,''), last_seen, active FROM customers WHERE id = ?`, id,
	).Scan(&c.ID, &c.PubKey, &c.VPNIP, &c.PiID, &c.LastSeen, &c.Active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &c, err
}

func (s *store) upsertCustomer(id, pubKey, vpnIP, piID string) error {
	_, err := s.db.Exec(`
		INSERT INTO customers(id, pubkey, vpn_ip, pi_id)
		VALUES(?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET pubkey=excluded.pubkey, pi_id=excluded.pi_id
	`, id, pubKey, vpnIP, piID)
	return err
}

func (s *store) customersByPi(piID string) ([]CustomerRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, COALESCE(pubkey,''), vpn_ip, COALESCE(pi_id,''), last_seen, active FROM customers WHERE pi_id = ? AND active = 1`, piID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomerRecord
	for rows.Next() {
		var c CustomerRecord
		if err := rows.Scan(&c.ID, &c.PubKey, &c.VPNIP, &c.PiID, &c.LastSeen, &c.Active); err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ── access codes ──────────────────────────────────────────────────────────────

func (s *store) validateCode(code string) (network string, usedBy string, ok bool) {
	err := s.db.QueryRow(
		`SELECT network, COALESCE(used_by,'') FROM access_codes WHERE code = ?`, code,
	).Scan(&network, &usedBy)
	if err != nil {
		return "", "", false
	}
	return network, usedBy, true
}

func (s *store) bindCode(code, customerID string) error {
	_, err := s.db.Exec(`UPDATE access_codes SET used_by = ? WHERE code = ?`, customerID, code)
	return err
}

func (s *store) insertCode(code, network string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO access_codes(code, network) VALUES(?,?)`, code, network)
	return err
}

// ── IP allocation ─────────────────────────────────────────────────────────────
// Pi IPs:       10.100.0.2  – 10.100.9.254    (up to ~2286 Pis)
// Customer IPs: 10.100.10.1 – 10.100.254.254  (up to ~61,950 customers)
// Both pools are sequential; to reclaim deleted IPs add a free-list table later.

func (s *store) nextPiIP() (string, error) {
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM pis`).Scan(&count)
	return seqIP(10, 100, 0, 2, count, 2540)
}

func (s *store) nextCustomerIP() (string, error) {
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM customers`).Scan(&count)
	return seqIP(10, 100, 10, 1, count, 61950)
}

// seqIP computes the Nth sequential address starting at a.b.c.d.
func seqIP(a, b, startC, startD, n, cap int) (string, error) {
	if n >= cap {
		return "", fmt.Errorf("IP pool exhausted (cap %d)", cap)
	}
	// Flatten starting address into an offset, add n, un-flatten.
	base := startC*254 + (startD - 1)
	total := base + n
	c := total / 254
	d := total%254 + 1
	return fmt.Sprintf("%d.%d.%d.%d/32", a, b, c, d), nil
}
