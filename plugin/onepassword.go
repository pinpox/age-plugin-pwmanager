package plugin

import (
	"bufio"
	"bytes"
	"strings"

	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"

	page "filippo.io/age/plugin"

	"golang.org/x/crypto/ssh"
)

type OnePassword struct{}

func (opw OnePassword) ReadKeyFromPath(path string) (key []byte, err error) {
	// Log.Printf("reading path from 1Password: %s", path)
	cmd := exec.Command("op", "read", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("could not read key from 1Password at: %v: %v", path, err)
	}
	return output, nil
}

func (opw OnePassword) ListSSHFingerprints() (output []byte, err error) {
	cmd := exec.Command("op", "item", "list", "--categories", "SSH Key", "--format=json")
	output, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("could not get list of SSH keys from 1Password: %v", err)
	}
	return
}

func (opw OnePassword) UnmarshalItemList(output []byte) (items []map[string]any, err error) {
	err = json.Unmarshal(output, &items)
	if err != nil {
		return nil, fmt.Errorf("could not decode list of SSH keys from 1Password: %v", err)
	}
	return
}

func (opw OnePassword) ReadKeyFromPubKey(pubKey ssh.PublicKey) (privateKey []byte, err error) {
	fingerprint := ssh.FingerprintSHA256(pubKey)
	Log.Printf("fingerprint=%s", fingerprint)

	output, err := opw.ListSSHFingerprints()
	if err != nil {
		return nil, err
	}

	items, err := opw.UnmarshalItemList(output)
	if err != nil {
		return nil, err
	}

	var privateKeyPath string

	for _, item := range items {
		additional_information := item["additional_information"].(string)

		if additional_information == fingerprint {
			vault := item["vault"].(map[string]interface{})
			privateKeyPath = fmt.Sprintf("op://%s/%s/private key", vault["id"], item["id"])
			break
		}
	}

	if privateKeyPath == "" {
		return nil, fmt.Errorf("private key not found in 1Password for public key: %s", ssh.MarshalAuthorizedKey(pubKey))
	}

	return opw.ReadKeyFromPath(privateKeyPath)
}

func (opw OnePassword) ReadAllKeys() (privateKeyFromOpRef map[string][]byte, err error) {
	opItemList := exec.Command("op", "item", "list", "--categories", "SSH Key", "--format=json")
	opItemGet := exec.Command("op", "item", "get", "-", "--fields", "private_key", "--format=json")

	outPipe, err := opItemList.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to list SSH keys from 1Password: %v", err)
	}
	defer outPipe.Close()

	opItemList.Start()
	opItemGet.Stdin = outPipe
	output, err := opItemGet.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get SSH keys from 1Password: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(output))
	privateKeyFromOpRef = make(map[string][]byte)

	for {
		var item map[string]interface{}
		err := decoder.Decode(&item)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to decode SSH keys from 1Password: %v", err)
		}

		value := []byte(item["value"].(string))
		reference := item["reference"].(string)
		privateKeyFromOpRef[reference] = value
	}
	return
}

func (opw OnePassword) CreateIdentityFromPath(privateKeyPath string) (*Identity, error) {
	privateKey, err := opw.ReadKeyFromPath(privateKeyPath)
	if err != nil {
		return nil, err
	}

	return NewIdentity(privateKey)
}

func (opw OnePassword) GetAllIdentities() (identities []Identity, err error) {
	privateKeyForRef, err := opw.ReadAllKeys()
	if err != nil {
		return nil, err
	}

	for _, privateKey := range privateKeyForRef {
		i, err := NewIdentity(privateKey)
		if err != nil {
			return nil, err
		}
		identities = append(identities, *i)
	}
	return
}

func (opw OnePassword) MarshalAllRecipients() (out string, err error) {
	privateKeysForOpRef, err := opw.ReadAllKeys()
	if err != nil {
		return "", err
	}
	for opRef, privateKey := range privateKeysForOpRef {
		identity, err := NewIdentity(privateKey)
		if err != nil {
			return "", err
		}

		out += fmt.Sprintf("%s: %s\n", opRef, identity.Recipient())
	}
	return
}

func (opw OnePassword) DecodeIdentity(s string) (*Identity, error) {
	var key Identity
	name, b, err := page.ParseIdentity(s)
	if err != nil {
		return nil, err
	}
	if name != PluginName {
		return nil, fmt.Errorf("invalid hrp")
	}
	r := bytes.NewBuffer(b)
	for _, f := range key.Serialize() {
		if err := binary.Read(r, binary.BigEndian, f); err != nil {
			return nil, err
		}
	}

	publicKey, err := ssh.ParsePublicKey(r.Bytes())
	if err != nil {
		return nil, err
	}

	key.PubKey = publicKey

	privateKey, err := opw.ReadKeyFromPubKey(publicKey)
	if err != nil {
		return nil, err
	}

	key.privateKey = privateKey

	return &key, nil
}

func (opw OnePassword) ParseIdentity(f io.Reader) (*Identity, error) {
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

		identity, err := opw.DecodeIdentity(line)
		if err != nil {
			return nil, fmt.Errorf("error at line %d: %v", n, err)
		}
		return identity, nil
	}
	return nil, fmt.Errorf("no identities found")
}

func (opw OnePassword) NewDefaultIdentity() (*DefaultIdentity, error) {
	d := new(DefaultIdentity)
	identities, err := opw.GetAllIdentities()
	if err != nil {
		return nil, err
	}
	d.identities = identities
	return d, nil
}
