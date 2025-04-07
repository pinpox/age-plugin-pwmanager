package plugin

import (
	"errors"
	"fmt"
	"io"
	"log"
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
	// The reference is a path or ID inside the password manager backend
	CreateIdentityFromPath(privateKeyPath string) (*Identity, error)

	ParseIdentity(f io.Reader) (*Identity, error)

	// DecodeIdentity constructs an Identity from a pluginIdentityString.
	DecodeIdentity(pluginIdentityString string) (*Identity, error)
	NewDefaultIdentity() (*DefaultIdentity, error)

	MarshalAllRecipients() (out string, err error)
}

func NewManager(backend string, w io.Writer) (PwManager, error) {

	Log = log.New(w, "", log.Lshortfile)

	switch backend {
	case "1password":
		log.Println("Using 1Password as backend")
		return OnePassword{}, nil
	case "bitwarden":
		log.Println("Using Bitwarden as backend")
		return Bitwarden{}, nil
	default:

		message := fmt.Sprintf("%s is not a supported manager. Valid options are '1password' and 'bitwarden'", backend)
		return nil, errors.New(message)

	}

}
