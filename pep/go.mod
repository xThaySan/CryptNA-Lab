module cryptna-lab/pep

go 1.23

require (
	cryptna-lab/common/cryptoutil v0.0.0
	cryptna-lab/common/ipsecutil v0.0.0
	cryptna-lab/common/protocol v0.0.0
)

require (
	cryptna-lab/common/logutil v0.0.0
	golang.org/x/crypto v0.33.0 // indirect
)

replace cryptna-lab/common/cryptoutil => ../common/cryptoutil

replace cryptna-lab/common/protocol => ../common/protocol

replace cryptna-lab/common/logutil => ../common/logutil

replace cryptna-lab/common/ipsecutil => ../common/ipsecutil

replace cryptna-lab/common/nattutil => ../common/nattutil
