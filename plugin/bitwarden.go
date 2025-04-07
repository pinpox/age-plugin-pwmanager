package plugin

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
)

type Bitwarden struct{}

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

func (bwi BwSshItem) toIdentity() (*Identity, error) {
	return NewIdentity([]byte(bwi.SSHKey.PrivateKey))
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
//     "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3...lF\n-----END OPENSSH PRIVATE KEY-----\n",
//     "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB4WccXD32kcOUzyYgcT3b5yzwsD71U0yorjN4O4d6m",
//     "keyFingerprint": "SHA256:0dRkX4RpEIbWWnWRZbQwqbEMd1yrPlUT/iYTelwQQHc"
//   },
//   "collectionIds": []
// }

// or:
// bw get item 9f08782a-209a-4d31-b1bf-8aa05a6233a0

func (bw Bitwarden) BwSshItems() (items []BwSshItem, err error) {

	var allItems = []BwSshItem{}

	cmd := exec.Command("bw", "list", "items", "--raw")

	output, err := cmd.Output()
	if err != nil {
		log.Println("Error executing bw-cli")
		return items, err
	}

	if err := json.Unmarshal(output, &allItems); err != nil {
		log.Println("Error parsing bw output", string(output))
		return items, err
	}

	// Filter for "type = 5" (The SSH-Key type in bitwarden)
	for _, item := range allItems {
		if item.Type == 5 {
			items = append(items, item)
		}
	}

	return
}

func (bw Bitwarden) DecodeIdentity(pluginIdentityString string) (*Identity, error) {
	log.Println("Trying to decode string:", pluginIdentityString)
	// TODO implement
	// Used by main
	return nil, nil
}

func (bw Bitwarden) NewDefaultIdentity() (*DefaultIdentity, error) {

	d := new(DefaultIdentity)
	identities := []Identity{}

	allkeys, err := bw.BwSshItems()
	if err != nil {
		return nil, err
	}

	for _, key := range allkeys {
		i, err := NewIdentity([]byte(key.SSHKey.PrivateKey))
		if err != nil {
			return nil, err
		}
		identities = append(identities, *i)
	}

	d.identities = identities
	return d, nil
}

// MarshalAllRecipients returns all recipients (public keys) from the vault in
// a readable format, e.g.:
// f441244b-cba4-403e-92dc-b00b3bd7428b (me@host1): ssh-ed25519 AAAAC3NzaCxxxxxxxxxxxxxxxxxxxxxxx
// 9fa82648-e32f-4127-acb2-69b052a88485 (me@host2): ssh-ed25519 AAAAC3NzaCxxxxxxxxxxxxxxxxxxxxxxx
func (bw Bitwarden) MarshalAllRecipients() (out string, err error) {

	var items []BwSshItem

	if items, err = bw.BwSshItems(); err != nil {
		return
	}

	for _, item := range items {
		if identity, err := item.toIdentity(); err != nil {
			return "", err
		} else {
			out += fmt.Sprintf("%s (%s): %s\n", item.ID, item.Name, identity.Recipient())
		}
	}

	return
}

func (bw Bitwarden) CreateIdentityFromPath(keyRef string) (*Identity, error) {

	items, err := bw.BwSshItems()
	if err != nil {
		return nil, err
	}

	// Find first item who's name or ID matches
	for _, item := range items {
		if item.ID == keyRef || item.Name == strings.TrimSpace(keyRef) {
			return item.toIdentity()
		}
	}

	return nil, errors.New("No matching idententy found for: " + keyRef)
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
