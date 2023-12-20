module wireguard-go

go 1.17

require (
	github.com/google/uuid v1.3.0
	golang.org/x/sys v0.5.0
	golang.zx2c4.com/wireguard v0.0.0-00010101000000-000000000000
	golang.zx2c4.com/wireguard/windows v0.5.3
)

require (
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3 // indirect
	golang.org/x/net v0.0.0-20211215060638-4ddde0e984e9 // indirect
)

replace golang.zx2c4.com/wireguard => github.com/mathiaspeters/wireguard-go v0.0.0-20211017052713-f87e87af0d9a
