# CRYPTNA security notes

## UDP source spoofing before PEP activation

In the current laboratory prototype, the PDP activates the PEP after a valid SPA packet is opened and authorized. The PEP receives the client outer address from the PDP, where it is derived from the UDP source address observed on the WAN-facing SPA packet.

This means the client never declares its outer IP address and the PIP does not store it. However, UDP source addresses can be spoofed on some networks. A spoofed SPA packet cannot receive the encrypted PDP response, but if the packet is otherwise valid, it could ask the PDP to activate a PEP session for the spoofed source address.

This risk is accepted for the current v0 one-shot SPA design and must be revisited later. Possible mitigations include rate limiting, anti-spoofing at the network edge, a challenge/confirmation step before PEP activation, or binding activation to a return-reachability proof while preserving the stealth properties of CRYPTNA.


## PDP-owned PEP endpoint selection

The PEP WAN endpoint returned to the client is selected and inserted by the PDP.
The PEP activation response intentionally does not contain `pep_address` or `pep_port`;
those values are orchestration data known by the PDP. This avoids making the PEP
self-declare its WAN address and keeps the client-facing endpoint decision in the
control plane.

## Client outer IP trust boundary

The client never declares its outer IP in the SPA payload. The PDP derives
`client_outer_ip` only from the UDP source address observed on the WAN-facing SPA
packet and passes that value to the selected PEP for XFRM/NAT-T state creation.
