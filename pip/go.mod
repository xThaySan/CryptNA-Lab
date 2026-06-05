module cryptna-lab/pip

go 1.23

require (
	cryptna-lab/common/logutil v0.0.0
	cryptna-lab/common/protocol v0.0.0
	github.com/mattn/go-sqlite3 v1.14.24
)

replace cryptna-lab/common/protocol => ../common/protocol

replace cryptna-lab/common/logutil => ../common/logutil
