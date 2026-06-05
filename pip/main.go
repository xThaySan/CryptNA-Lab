package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"cryptna-lab/common/protocol"
	_ "github.com/mattn/go-sqlite3"
	"cryptna-lab/common/logutil"
)

func main() {
	db, err := sql.Open("sqlite3", "/data/pip.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	initDB(db)
	seedClients(db, "/app/clients.json")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc("/clients/", func(w http.ResponseWriter, r *http.Request) {
		clientPubKey := strings.TrimPrefix(r.URL.Path, "/clients/")
		if clientPubKey == "" {
			http.Error(w, "missing client public key", http.StatusBadRequest)
			return
		}
		logutil.Debugf("pip", "lookup client=%s", logutil.Short(clientPubKey))

		client, err := getClient(db, clientPubKey)
		if err == sql.ErrNoRows {
			http.Error(w, "client not found", http.StatusNotFound)
			logutil.Debugf("pip", "client not found=%s", logutil.Short(clientPubKey))
			return
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			log.Println("get client:", err)
			return
		}
		logutil.Debugf("pip", "client found=%s services=%v revoked=%v", logutil.Short(client.ClientPubKey), client.AllowedServices, client.Revoked)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(client)
	})

	logutil.Infof("pip", "listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initDB(db *sql.DB) {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS clients (
		client_pubkey TEXT PRIMARY KEY,
		psk TEXT NOT NULL,
		allowed_services TEXT NOT NULL,
		revoked INTEGER NOT NULL DEFAULT 0
	);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func seedClients(db *sql.DB, path string) {
	logutil.Debugf("pip", "loading seed file path=%s", path)

	f, err := os.Open(path)
	if err != nil {
		log.Printf("no seed file found at %s: %v", path, err)
		return
	}
	defer f.Close()

	var clients []protocol.ClientInfo
	if err := json.NewDecoder(f).Decode(&clients); err != nil {
		log.Fatalf("decode seed file: %v", err)
	}

	for _, c := range clients {
		services := strings.Join(c.AllowedServices, ",")
		revoked := 0
		if c.Revoked {
			revoked = 1
		}

		_, err := db.Exec(`
		INSERT OR REPLACE INTO clients
		(client_pubkey, psk, allowed_services, revoked)
		VALUES (?, ?, ?, ?);
		`, c.ClientPubKey, c.PSK, services, revoked)

		if err != nil {
			log.Fatalf("seed client %s: %v", c.ClientPubKey, err)
		}
		logutil.Debugf("pip", "seeded client=%s services=%v revoked=%v", logutil.Short(c.ClientPubKey), c.AllowedServices, c.Revoked)
	}
	
}

func getClient(db *sql.DB, pubkey string) (protocol.ClientInfo, error) {
	var c protocol.ClientInfo
	var services string
	var revoked int

	err := db.QueryRow(`
	SELECT client_pubkey, psk, allowed_services, revoked
	FROM clients
	WHERE client_pubkey = ?;
	`, pubkey).Scan(&c.ClientPubKey, &c.PSK, &services, &revoked)

	if err != nil {
		return c, err
	}

	c.AllowedServices = strings.Split(services, ",")
	c.Revoked = revoked != 0
	return c, nil
}
