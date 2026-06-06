package protocol

// AccessPayload is the business payload encrypted as nm in the SPA.
// The client identity and timestamp are deliberately not here: they are
// encrypted in ns as timestamp_ms || client_static_pub, matching CRYPTNA's SPA layout.
//
// SPI naming follows the IPsec receiver-owned convention:
// - ClientInSPI is chosen by the client and used by the client to receive PEP -> Client traffic.
// - PEPInSPI is chosen by the PEP and used by the PEP to receive Client -> PEP traffic.
type AccessPayload struct {
	ServiceID   string   `json:"service_id"`
	ClientInSPI string   `json:"client_in_spi"`
	ClientDHPub string   `json:"client_dh_pub"`
	AEADSuites  []string `json:"aead_suites"`
}

type ActivateRequest struct {
	ClientPubKey string   `json:"client_pubkey"`
	ServiceID    string   `json:"service_id"`
	ClientInSPI  string   `json:"client_in_spi"`
	ClientDHPub  string   `json:"client_dh_pub"`
	AEADSuites   []string `json:"aead_suites"`
}

type AccessResponse struct {
	Authorized bool          `json:"authorized"`
	Reason     string        `json:"reason"`
	Tunnel     *TunnelParams `json:"tunnel,omitempty"`
}

type TunnelParams struct {
	ServiceID     string `json:"service_id"`
	PEPAddress    string `json:"pep_address"`
	PEPPort       int    `json:"pep_port"`
	ClientInSPI   string `json:"client_in_spi"`
	PEPInSPI      string `json:"pep_in_spi"`
	ClientInnerIP string `json:"client_inner_ip"`
	PEPDHPub      string `json:"pep_dh_pub"`
	AEAD          string `json:"aead"`
	SALifetime    int    `json:"sa_lifetime_seconds"`
	ExpiresAt     string `json:"expires_at"`
}

type ClientInfo struct {
	ClientPubKey    string   `json:"client_pubkey"`
	PSK             string   `json:"psk"`
	AllowedServices []string `json:"allowed_services"`
	Revoked         bool     `json:"revoked"`
}

type XFRMPlan struct {
	Mode           string   `json:"mode"`
	Commands       []string `json:"commands"`
	DeleteCommands []string `json:"delete_commands,omitempty"`
}

// XFRMDryRun is kept as an alias for compatibility with existing code/tests.
type XFRMDryRun = XFRMPlan

type Session struct {
	ClientPubKey  string   `json:"client_pubkey"`
	ServiceID     string   `json:"service_id"`
	ReqID         uint32   `json:"reqid"`
	ClientInSPI   string   `json:"client_in_spi"`
	PEPInSPI      string   `json:"pep_in_spi"`
	ClientOuterIP string   `json:"client_outer_ip"`
	ClientInnerIP string   `json:"client_inner_ip"`
	PEPOuterIP    string   `json:"pep_outer_ip"`
	ServiceIP     string   `json:"service_ip"`
	ClientDHPub   string   `json:"client_dh_pub"`
	PEPDHPub      string   `json:"pep_dh_pub"`
	AEAD          string   `json:"aead"`
	C2PKey        string   `json:"c2p_key"`
	P2CKey        string   `json:"p2c_key"`
	ExpiresAt     string   `json:"expires_at"`
	XFRM          XFRMPlan `json:"xfrm"`
}
