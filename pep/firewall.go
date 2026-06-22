package main

import (
	"fmt"
	"os/exec"

	"cryptna-lab/common/logutil"
)

func setupPEPFirewall() error {
	enabled := getenv("PEP_FIREWALL_ENABLED", "1")
	if enabled != "1" && enabled != "true" && enabled != "TRUE" {
		logutil.Infof("pep", "PEP firewall disabled")
		return nil
	}

	clientCIDR := getenv("CLIENT_TUNNEL_CIDR", "10.200.0.0/16")
	serviceIP := getenv("SERVICE_IP", "172.22.0.50")
	servicePort := getenvInt("SERVICE_PORT", 80)

	logutil.Infof("pep", "configuring PEP firewall client_cidr=%s service=%s:%d",
		clientCIDR, serviceIP, servicePort)

	commands := []string{
		// Reset only FORWARD in the PEP namespace.
		"iptables -F FORWARD",
		"iptables -P FORWARD DROP",

		// Allow tunnel clients to reach only the protected service port.
		fmt.Sprintf(
			"iptables -A FORWARD -s %s -d %s/32 -p tcp --dport %d -j ACCEPT",
			clientCIDR, serviceIP, servicePort,
		),

		// Allow service replies back to tunnel clients.
		fmt.Sprintf(
			"iptables -A FORWARD -s %s/32 -d %s -p tcp --sport %d -j ACCEPT",
			serviceIP, clientCIDR, servicePort,
		),

		// Explicit final drop for readability.
		"iptables -A FORWARD -j DROP",
	}

	for _, cmd := range commands {
		logutil.Infof("pep", "applying firewall: %s", cmd)

		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			return fmt.Errorf("firewall command failed: %s: %v: %s", cmd, err, string(out))
		}
	}

	return nil
}
