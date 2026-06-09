package protocol

// AccessPayload is the encrypted SPA business payload sent by the client to the PDP.
// The client chooses ClientInSPI because it is the receiver for PEP -> Client traffic.
type AccessPayload struct {
	ServiceID   string   `json:"service_id"`
	ClientInSPI string   `json:"client_in_spi"`
	ClientDHPub string   `json:"client_dh_pub"`
	AEADSuites  []string `json:"aead_suites"`
}

// ActivateRequest is sent by the PDP to the PEP after SPA validation and policy authorization.
type ActivateRequest struct {
	ClientPubKey string `json:"client_pubkey"`
	// ClientOuterIP is observed by the PDP from the UDP SPA source address.
	// It is never declared by the client and must not come from the PIP.
	ClientOuterIP string   `json:"client_outer_ip"`
	ServiceID     string   `json:"service_id"`
	ClientInSPI   string   `json:"client_in_spi"`
	ClientDHPub   string   `json:"client_dh_pub"`
	AEADSuites    []string `json:"aead_suites"`
}

type AccessResponse struct {
	Authorized bool          `json:"authorized"`
	Reason     string        `json:"reason"`
	Tunnel     *TunnelParams `json:"tunnel,omitempty"`
}

// PEPActivationResponse is returned by the PEP to the PDP after local activation.
// It intentionally does not contain the PEP WAN address/port: the PDP selects the
// PEP and is responsible for inserting the client-facing PEP endpoint in TunnelParams.
type PEPActivationResponse struct {
	ServiceID string `json:"service_id"`
	ServiceIP string `json:"service_ip"`

	ClientInnerIP string `json:"client_inner_ip"` // Per-session inner source IP assigned by the PEP.
	ClientInSPI   string `json:"client_in_spi"`   // Chosen by the client, used for PEP -> Client.
	PEPInSPI      string `json:"pep_in_spi"`      // Chosen by the PEP, used for Client -> PEP.

	PEPDHPub   string `json:"pep_dh_pub"`
	AEAD       string `json:"aead"`
	SALifetime int    `json:"sa_lifetime_seconds"`
	ExpiresAt  string `json:"expires_at"`
}

// TunnelParams are returned by the PDP to the client after PEP activation.
// The PEP endpoint fields are populated by the PDP, not by the PEP.
// The client agent uses these values to install IPsec/XFRM locally; they are not
// meant to be displayed to the end user.
type TunnelParams struct {
	ServiceID  string `json:"service_id"`
	ServiceIP  string `json:"service_ip"`
	PEPAddress string `json:"pep_address"`
	PEPPort    int    `json:"pep_port"` // IPsec NAT-T UDP port, usually 4500.

	ClientInnerIP string `json:"client_inner_ip"` // Per-session inner source IP assigned by the PEP.
	ClientInSPI   string `json:"client_in_spi"`   // Chosen by the client, used for PEP -> Client.
	PEPInSPI      string `json:"pep_in_spi"`      // Chosen by the PEP, used for Client -> PEP.

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

type XFRMPlan struct {
	Mode           string   `json:"mode"`
	Commands       []string `json:"commands"`
	DeleteCommands []string `json:"delete_commands,omitempty"`
}

type Session struct {
	ClientPubKey string `json:"client_pubkey"`
	ServiceID    string `json:"service_id"`

	ReqID       uint32 `json:"reqid"`
	ClientInSPI string `json:"client_in_spi"`
	PEPInSPI    string `json:"pep_in_spi"`

	ClientOuterIP string `json:"client_outer_ip"`
	ClientInnerIP string `json:"client_inner_ip"`
	PEPOuterIP    string `json:"pep_outer_ip"`
	ServiceIP     string `json:"service_ip"`
	NATTPort      int    `json:"natt_port"`

	ClientDHPub string `json:"client_dh_pub"`
	PEPDHPub    string `json:"pep_dh_pub"`

	AEAD      string `json:"aead"`
	C2PKey    string `json:"c2p_key"`
	P2CKey    string `json:"p2c_key"`
	ExpiresAt string `json:"expires_at"`

	XFRM XFRMPlan `json:"xfrm"`
}
