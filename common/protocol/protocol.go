package protocol

// AccessPayload is the business payload encrypted as nm in the SPA.
// The client identity and timestamp are deliberately not here: they are
// encrypted in ns as timestamp_ms || client_static_pub, matching CRYPTNA's SPA layout.
type AccessPayload struct {
	ServiceID   string   `json:"service_id"`
	ClientSPI   string   `json:"client_spi"`
	ClientDHPub string   `json:"client_dh_pub"`
	AEADSuites  []string `json:"aead_suites"`
}

type ActivateRequest struct {
	ClientPubKey string   `json:"client_pubkey"`
	ServiceID    string   `json:"service_id"`
	ClientSPI    string   `json:"client_spi"`
	ClientDHPub  string   `json:"client_dh_pub"`
	AEADSuites   []string `json:"aead_suites"`
}

type AccessResponse struct {
	Authorized bool          `json:"authorized"`
	Reason     string        `json:"reason"`
	Tunnel     *TunnelParams `json:"tunnel,omitempty"`
}

type TunnelParams struct {
	ServiceID  string `json:"service_id"`
	PEPAddress string `json:"pep_address"`
	PEPPort    int    `json:"pep_port"`
	PEPSPI     string `json:"pep_spi"`
	PEPDHPub   string `json:"pep_dh_pub"`
	AEAD       string `json:"aead"`
	SALifetime int    `json:"sa_lifetime_seconds"`
	ExpiresAt  string `json:"expires_at"`
}

type ClientInfo struct {
	ClientPubKey    string   `json:"client_pubkey"`
	PSK             string   `json:"psk"`
	AllowedServices []string `json:"allowed_services"`
	Revoked         bool     `json:"revoked"`
}

type Session struct {
	ClientPubKey string `json:"client_pubkey"`
	ServiceID    string `json:"service_id"`
	ClientSPI    string `json:"client_spi"`
	PEPSPI       string `json:"pep_spi"`
	ClientDHPub  string `json:"client_dh_pub"`
	PEPDHPub     string `json:"pep_dh_pub"`
	AEAD         string `json:"aead"`
	C2PKey       string `json:"c2p_key"`
	P2CKey       string `json:"p2c_key"`
	ExpiresAt    string `json:"expires_at"`
}
