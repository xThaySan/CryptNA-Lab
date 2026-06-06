package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"cryptna-lab/common/nattutil"
)

func main() {
	port := flag.Int("port", 4500, "UDP NAT-T port")
	flag.Parse()

	sock, err := nattutil.ListenESPInUDP(*port)
	if err != nil {
		log.Fatal(err)
	}
	defer sock.Close()

	log.Printf("NAT-T ESP-in-UDP socket listening on :%d", *port)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
