package nattutil

import (
	"fmt"
	"syscall"
)

const (
	udpEncap         = 100
	udpEncapESPInUDP = 2
)

type Socket struct {
	fd   int
	Port int
}

func ListenESPInUDP(port int) (*Socket, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("socket udp/%d: %w", port, err)
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("setsockopt reuseaddr udp/%d: %w", port, err)
	}

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_UDP, udpEncap, udpEncapESPInUDP); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("setsockopt UDP_ENCAP_ESPINUDP udp/%d: %w", port, err)
	}

	addr := &syscall.SockaddrInet4{
		Port: port,
		Addr: [4]byte{0, 0, 0, 0},
	}

	if err := syscall.Bind(fd, addr); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("bind udp/%d: %w", port, err)
	}

	return &Socket{fd: fd, Port: port}, nil
}

func (s *Socket) Close() error {
	if s == nil || s.fd < 0 {
		return nil
	}
	err := syscall.Close(s.fd)
	s.fd = -1
	return err
}
