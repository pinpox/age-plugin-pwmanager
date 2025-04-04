package plugin

import (
	"io"
)

type Bitwarden struct{}

func (bw Bitwarden) CreateIdentityFromPath(privateKeyPath string) (*Identity, error) {
	// TODO implement
	return nil, nil
}

func (bw Bitwarden) DecodeIdentity(s string) (*Identity, error) {
	// TODO implement
	return nil, nil
}

func (bw Bitwarden) ParseIdentity(f io.Reader) (*Identity, error) {
	// TODO implement
	return nil, nil
}

func (bw Bitwarden) NewDefaultIdentity() (*DefaultIdentity, error) {
	// TODO implement
	return nil, nil
}
