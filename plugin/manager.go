package plugin

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

const (
	PluginName = "pwmanager"
)

var (
	Log     *log.Logger
	Backend string
)

type PwManager interface {

	// CreateIdentityFromPath creates a new identity from a given reference.
	// The reference is a path or ID or the name inside the password manager
	// backend
	CreateIdentityFromPath(privateKeyPath string) (*Identity, error)

	ParseIdentity(f io.Reader) (*Identity, error)

	// DecodeIdentity constructs an Identity from a pluginIdentityString.
	DecodeIdentity(pluginIdentityString string) (*Identity, error)

	// NewDefaultIdentity constructs a DefaultIdentity, which is a list of all
	// SSH-Keys found in the vault
	NewDefaultIdentity() (*DefaultIdentity, error)

	// MarshalAllRecipients returns all recipients (public keys) from the vault in
	// a readable format, e.g.:
	// f441244b-cba4-403e-92dc-b00b3bd7428b (me@host1): ssh-ed25519 AAAAC3NzaCxxxx...
	// 9fa82648-e32f-4127-acb2-69b052a88485 (me@host2): ssh-ed25519 AAAAC3NzaCxxxx...
	MarshalAllRecipients() (out string, err error)
}

func NewManager(w io.Writer) (PwManager, error) {

	Log = log.New(w, "", log.Lshortfile)
	backend := os.Getenv("AGE_PW_BACKEND")

	switch backend {
	case "1password":
		log.Println("Using 1Password as backend")
		return OnePassword{}, nil
	case "bitwarden":
		log.Println("Using Bitwarden as backend")
		return Bitwarden{}, nil
	default:
		message := fmt.Sprintf("'%s' is not a supported manager. Set AGE_PW_BACKEND to '1password' or 'bitwarden'", backend)
		return nil, errors.New(message)
	}

}
