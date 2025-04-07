package plugin

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"strings"
)

type Bitwarden struct{}

var testPublicKey []byte
var testPrivateKey []byte

// To get all ssh keys in the bitwarden vault:
// bw list items | jq '[.[] | select(.type == 5)]'

// To get a key by name or id from the bitwarden vault:
// bw get item pinpox@bitwarden

type BwSshItem struct {
	// PasswordHistory interface{} `json:"passwordHistory"`
	// RevisionDate    time.Time   `json:"revisionDate"`
	// CreationDate    time.Time   `json:"creationDate"`
	// DeletedDate     interface{} `json:"deletedDate"`
	// Object          string      `json:"object"`
	ID string `json:"id"`
	// OrganizationID  interface{} `json:"organizationId"`
	// FolderID        interface{} `json:"folderId"`
	Type int `json:"type"`
	// Reprompt        int         `json:"reprompt"`
	Name string `json:"name"`
	// Notes           interface{} `json:"notes"`
	// Favorite        bool        `json:"favorite"`
	SSHKey struct {
		PrivateKey     string `json:"privateKey"`
		PublicKey      string `json:"publicKey"`
		KeyFingerprint string `json:"keyFingerprint"`
	} `json:"sshKey"`
	// CollectionIds []interface{} `json:"collectionIds"`
}

// Example test key
// {
//   "passwordHistory": null,
//   "revisionDate": "2025-04-05T11:38:32.253Z",
//   "creationDate": "2025-04-05T11:38:32.252Z",
//   "deletedDate": null,
//   "object": "item",
//   "id": "ce3e36d1-271c-4019-9679-3244c41797e7",
//   "organizationId": null,
//   "folderId": null,
//   "type": 5,
//   "reprompt": 0,
//   "name": "testkey@bitwarden",
//   "notes": null,
//   "favorite": false,
//   "sshKey": {
//     "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACAweFnHFw99pHDlM8mIHE92+cs8LA+9VNMqK4zeDuHepgAAAIgH0TjwB9E4\n8AAAAAtzc2gtZWQyNTUxOQAAACAweFnHFw99pHDlM8mIHE92+cs8LA+9VNMqK4zeDuHepg\nAAAEDFkYycB7AbRpStj8JOA7spFSSo3Q72G9er5cW+KOgo7TB4WccXD32kcOUzyYgcT3b5\nyzwsD71U0yorjN4O4d6mAAAAAAECAwQF\n-----END OPENSSH PRIVATE KEY-----\n",
//     "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB4WccXD32kcOUzyYgcT3b5yzwsD71U0yorjN4O4d6m",
//     "keyFingerprint": "SHA256:0dRkX4RpEIbWWnWRZbQwqbEMd1yrPlUT/iYTelwQQHc"
//   },
//   "collectionIds": []
// }

// or:
// bw get item 9f08782a-209a-4d31-b1bf-8aa05a6233a0

func (bw Bitwarden) DecodeIdentity(pluginIdentityString string) (*Identity, error) {
	log.Println("Trying to decode string:", pluginIdentityString)
	// TODO implement
	// Used by main
	return nil, nil
}

func (bw Bitwarden) NewDefaultIdentity() (*DefaultIdentity, error) {
	// TODO implement
	// Used by main
	return nil, nil
}

func (bw Bitwarden) MarshalAllRecipients() (out string, err error) {
	// TODO implement
	return "", nil
}

func (bw Bitwarden) CreateIdentityFromPath(privateKeyPath string) (*Identity, error) {
	// TODO implement
	return NewIdentity(testPrivateKey)
}

func (bw Bitwarden) ParseIdentity(f io.Reader) (*Identity, error) {
	// Same parser as age
	const privateKeySizeLimit = 1 << 24 // 16 MiB
	scanner := bufio.NewScanner(io.LimitReader(f, privateKeySizeLimit))
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		identity, err := bw.DecodeIdentity(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		return identity, nil
	}
	return nil, fmt.Errorf("no identities found")
}
