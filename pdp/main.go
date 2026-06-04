package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

type AccessRequest struct {
	ClientPubKey string `json:"client_pubkey"`
	ServiceID    string `json:"service_id"`
}

type ClientInfo struct {
	ClientPubKey     string   `json:"client_pubkey"`
	PSK             string   `json:"psk"`
	AllowedServices []string `json:"allowed_services"`
	Revoked         bool     `json:"revoked"`
}

type AccessResponse struct {
	Authorized bool   `json:"authorized"`
	Reason     string `json:"reason"`
}

func main() {
	pipURL := os.Getenv("PIP_URL")
	if pipURL == "" {
		pipURL = "http://cryptna-pip:8080"
	}

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

		writeJSON(w, AccessResponse{Authorized: true, Reason: "authorized"})
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
