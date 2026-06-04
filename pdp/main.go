package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

type AccessRequest struct {
	ClientPubKey string   `json:"client_pubkey"`
	ServiceID    string   `json:"service_id"`
	ClientSPI    string   `json:"client_spi"`
	ClientDHPub  string   `json:"client_dh_pub"`
	AEADSuites   []string `json:"aead_suites"`
}

type ClientInfo struct {
	ClientPubKey     string   `json:"client_pubkey"`
	PSK             string   `json:"psk"`
	AllowedServices []string `json:"allowed_services"`
	Revoked         bool     `json:"revoked"`
}

type AccessResponse struct {
	Authorized bool             `json:"authorized"`
	Reason     string           `json:"reason"`
	Tunnel     *ActivateResponse `json:"tunnel,omitempty"`
}

type ActivateResponse struct {
	ServiceID   string `json:"service_id"`
	PEPAddress string `json:"pep_address"`
	PEPPort    int    `json:"pep_port"`
	PEPSPI     string `json:"pep_spi"`
	PEPDHPub   string `json:"pep_dh_pub"`
	AEAD       string `json:"aead"`
	SALifetime int    `json:"sa_lifetime_seconds"`
	ExpiresAt  string `json:"expires_at"`
	DebugSharedSecret string `json:"debug_shared_secret"`
}

func main() {
	pipURL := getenv("PIP_URL", "http://cryptna-pip:8080")
	pepURL := getenv("PEP_URL", "http://cryptna-pep:8080")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/access", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req AccessRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		client, err := fetchClient(pipURL, req.ClientPubKey)
		if err != nil {
			writeJSON(w, AccessResponse{Authorized: false, Reason: "client not found or PIP error"})
			return
		}

		if client.Revoked {
			writeJSON(w, AccessResponse{Authorized: false, Reason: "client revoked"})
			return
		}

		if !contains(client.AllowedServices, req.ServiceID) {
			writeJSON(w, AccessResponse{Authorized: false, Reason: "service not allowed"})
			return
		}

		tunnel, err := activatePEP(pepURL, req)
		if err != nil {
			log.Println("activate PEP:", err)
			writeJSON(w, AccessResponse{Authorized: false, Reason: "PEP activation failed"})
			return
		}

		writeJSON(w, AccessResponse{
			Authorized: true,
			Reason:     "authorized",
			Tunnel:     &tunnel,
		})
	})

	log.Println("PDP listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func fetchClient(pipURL, pubkey string) (ClientInfo, error) {
	var c ClientInfo
	resp, err := http.Get(pipURL + "/clients/" + pubkey)
	if err != nil {
		return c, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c, http.ErrNoLocation
	}

	err = json.NewDecoder(resp.Body).Decode(&c)
	return c, err
}

func activatePEP(pepURL string, req AccessRequest) (ActivateResponse, error) {
	var out ActivateResponse

	body, err := json.Marshal(req)
	if err != nil {
		return out, err
	}

	resp, err := http.Post(pepURL+"/activate", "application/json", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return out, http.ErrNoLocation
	}

	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
