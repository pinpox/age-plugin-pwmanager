package plugin

import (
	"errors"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/ssh"
)

const (
	PluginName = "pwmanager"
)

var (
	Log     *log.Logger
	Backend string
)

type PwManager interface {
	ReadKeyFromPath(path string) (key []byte, err error)
	ListSSHFingerprints() (output []byte, err error)
	UnmarshalItemList(output []byte) (items []map[string]any, err error)
	ReadKeyFromPubKey(pubKey ssh.PublicKey) (privateKey []byte, err error)
	ReadAllKeys() (privateKeyFromOpRef map[string][]byte, err error)
	CreateIdentityFromPath(privateKeyPath string) (*Identity, error)
	GetAllIdentities() (identities []Identity, err error)
	MarshalAllRecipients() (out string, err error)
	ParseIdentity(f io.Reader) (*Identity, error)
	DecodeIdentity(s string) (*Identity, error)
	NewDefaultIdentity() (*DefaultIdentity, error)
}

func NewManager(backend string, w io.Writer) (PwManager, error) {

	Log = log.New(w, "", log.Lshortfile)

	switch backend {
	case "1password":
		return OnePassword{}, nil
	// case "bitwarden":
	// 	return Bitwarden{}, nil
	default:

		message := fmt.Sprintf("%s is not a supported manager. Valid options are '1password' and 'bitwarden'", backend)
		return nil, errors.New(message)

	}

}
