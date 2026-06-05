module cryptna-lab/tools/spa-send

go 1.23

require (
	cryptna-lab/common/cryptoutil v0.0.0
	cryptna-lab/common/noiseutil v0.0.0
	cryptna-lab/common/protocol v0.0.0
)

require golang.org/x/crypto v0.33.0 // indirect

replace cryptna-lab/common/cryptoutil => ../../common/cryptoutil

replace cryptna-lab/common/noiseutil => ../../common/noiseutil

replace cryptna-lab/common/protocol => ../../common/protocol
