package protocol

// AccessPayload is the encrypted SPA business payload sent by the client to the PDP.
// The client chooses ClientInSPI because it is the receiver for PEP -> Client traffic.
type AccessPayload struct {
	ServiceID   string   `json:"service_id"`
	ClientInSPI string   `json:"client_in_spi"`
	ClientDHPub string   `json:"client_dh_pub"`
	AEADSuites  []string `json:"aead_suites"`
}

// CapacityRequest is sent by the PEP to the Verifier to obtain a short-lived
// attested capability binding a temporary PEP signing key to an attested PEP state.
type CapacityRequest struct {
	PEPID            string           `json:"pep_id"`
	PEPSigningPubKey string           `json:"pep_signing_pubkey"`
	Measurement      string           `json:"measurement"`
	PolicyHash       string           `json:"policy_hash"`
	Scope            []string         `json:"scope"`
	MaxSALifetime    int              `json:"max_sa_lifetime_seconds"`
	History          *HistoryEvidence `json:"history,omitempty"`
}

// CapacityToken is signed by the Verifier. It authorizes the PEP to sign concrete
// SA bindings with PEPSigningPubKey for a bounded scope and time window.
type CapacityToken struct {
	Version          int      `json:"version"`
	TokenType        string   `json:"token_type"`
	VerifierID       string   `json:"verifier_id"`
	PEPID            string   `json:"pep_id"`
	PEPSigningPubKey string   `json:"pep_signing_pubkey"`
	Measurement      string   `json:"measurement"`
	PolicyHash       string   `json:"policy_hash"`
	Scope            []string `json:"scope"`
	IssuedAt         string   `json:"iat"`
	ExpiresAt        string   `json:"exp"`
	MaxSALifetime    int      `json:"max_sa_lifetime_seconds"`
	CheckpointHash   string   `json:"checkpoint_hash,omitempty"`
	HistoryEpoch     uint64   `json:"history_epoch,omitempty"`
	Signature        string   `json:"verifier_signature"`
}

// EnforcementEvent records one security-relevant action or observation performed by
// the PEP. Events are linked through PrevHash/EventHash to form an append-only
// history. The EventHash field is computed over the event with EventHash cleared.
type EnforcementEvent struct {
	Version       int               `json:"version"`
	Index         uint64            `json:"index"`
	EventType     string            `json:"event_type"`
	PEPID         string            `json:"pep_id"`
	Timestamp     string            `json:"timestamp"`
	ServiceID     string            `json:"service_id,omitempty"`
	ClientPubKey  string            `json:"client_pubkey,omitempty"`
	ClientOuterIP string            `json:"client_outer_ip,omitempty"`
	ClientInnerIP string            `json:"client_inner_ip,omitempty"`
	ClientInSPI   string            `json:"client_in_spi,omitempty"`
	PEPInSPI      string            `json:"pep_in_spi,omitempty"`
	ReqID         uint32            `json:"reqid,omitempty"`
	Observed      bool              `json:"observed,omitempty"`
	XFRMMode      string            `json:"xfrm_mode,omitempty"`
	XFRMPlanHash  string            `json:"xfrm_plan_hash,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	PrevHash      string            `json:"prev_hash"`
	EventHash     string            `json:"event_hash"`
}

// EnforcementCheckpoint summarizes the accepted enforcement history at a point in
// time. The PEP signs the checkpoint with the same temporary key later bound into
// the capacity token, proving possession of that key for the submitted history.
type EnforcementCheckpoint struct {
	Version                int    `json:"version"`
	PEPID                  string `json:"pep_id"`
	Epoch                  uint64 `json:"epoch"`
	PreviousCheckpointHash string `json:"previous_checkpoint_hash"`
	LastEventIndex         uint64 `json:"last_event_index"`
	LastEventHash          string `json:"last_event_hash"`
	EventCount             int    `json:"event_count"`
	CreatedAt              string `json:"created_at"`
	Signature              string `json:"pep_signature"`
}

// HistoryEvidence is sent by the PEP to the Verifier when requesting a capacity.
// It contains all events since the last checkpoint accepted by the Verifier and a
// signed checkpoint summarizing the resulting history state.
type HistoryEvidence struct {
	PreviousCheckpointHash string                `json:"previous_checkpoint_hash"`
	Events                 []EnforcementEvent    `json:"events"`
	Checkpoint             EnforcementCheckpoint `json:"checkpoint"`
}

// SABinding is signed by the attested PEP key referenced in CapacityToken.
// The client verifies this before installing local XFRM state.
type SABinding struct {
	Version       int    `json:"version"`
	TokenHash     string `json:"token_hash"`
	PEPID         string `json:"pep_id"`
	ClientPubKey  string `json:"client_pubkey"`
	ServiceID     string `json:"service_id"`
	ServiceIP     string `json:"service_ip"`
	ClientInnerIP string `json:"client_inner_ip"`
	ClientInSPI   string `json:"client_in_spi"`
	PEPInSPI      string `json:"pep_in_spi"`
	ClientDHPub   string `json:"client_dh_pub"`
	PEPDHPub      string `json:"pep_dh_pub"`
	AEAD          string `json:"aead"`
	SALifetime    int    `json:"sa_lifetime_seconds"`
	ExpiresAt     string `json:"expires_at"`
	Signature     string `json:"pep_signature"`
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

	CapacityToken *CapacityToken `json:"capacity_token,omitempty"`
	SABinding     *SABinding     `json:"sa_binding,omitempty"`
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

	CapacityToken *CapacityToken `json:"capacity_token,omitempty"`
	SABinding     *SABinding     `json:"sa_binding,omitempty"`
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
