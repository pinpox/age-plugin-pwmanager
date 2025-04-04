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
	CreateIdentityFromPath(privateKeyPath string) (*Identity, error)
	ParseIdentity(f io.Reader) (*Identity, error)
	DecodeIdentity(s string) (*Identity, error)
	NewDefaultIdentity() (*DefaultIdentity, error)
}

func NewManager(backend string, w io.Writer) (PwManager, error) {

	Log = log.New(w, "", log.Lshortfile)

	switch backend {
	case "1password":
		return OnePassword{}, nil
	case "bitwarden":
		return Bitwarden{}, nil
	default:

		message := fmt.Sprintf("%s is not a supported manager. Valid options are '1password' and 'bitwarden'", backend)
		return nil, errors.New(message)

	}

}
