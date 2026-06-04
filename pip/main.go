package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type ClientInfo struct {
	ClientPubKey     string   `json:"client_pubkey"`
	PSK             string   `json:"psk"`
	AllowedServices []string `json:"allowed_services"`
	Revoked         bool     `json:"revoked"`
}

func main() {
	db, err := sql.Open("sqlite3", "/data/pip.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	initDB(db)

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

		client, err := getClient(db, clientPubKey)
		if err == sql.ErrNoRows {
			http.Error(w, "client not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			log.Println("get client:", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(client)
	})

	log.Println("PIP listening on :8080")
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

	_, err = db.Exec(`
	INSERT OR IGNORE INTO clients
	(client_pubkey, psk, allowed_services, revoked)
	VALUES
	('client-static-pubkey-demo', 'psk-demo', 'svc-http', 0);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func getClient(db *sql.DB, pubkey string) (ClientInfo, error) {
	var c ClientInfo
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
