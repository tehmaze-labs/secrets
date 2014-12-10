package key

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/nacl/box"
)

const (
	// PEMPublicKey is the PEM encoding type for secrets public keys
	PEMPublicKey = "SECRETS PUBLIC KEY"
	// PEMPrivateKey is the PEM encoding type for secrets private keys
	PEMPrivateKey = "SECRETS PRIVATE KEY"
	// keySize is the default NaCL box key size (in bytes)
	keySize = 32
)

var (
	// OIDPublicKey is the ASN.1 object identifier for secrets public keys
	OIDPublicKey = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 27266, 11, 17, 1}
	// OIDPrivateKey is the ASN.1 object identifier for secrets private keys
	OIDPrivateKey = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 27266, 11, 17, 2}
)

// Key is a NaCL box key
type Key struct {
	ID         asn1.ObjectIdentifier
	PublicKey  []byte
	PrivateKey []byte `asn1:"omitempty"`
}

// BoxPublicKey returns the public key in NaCL box usable format
func (key *Key) BoxPublicKey() *[keySize]byte {
	out := new([keySize]byte)
	copy(out[:], key.PublicKey)
	return out
}

// BoxPrivateKey returns the public key in NaCL box usable format
func (key *Key) BoxPrivateKey() *[keySize]byte {
	out := new([keySize]byte)
	copy(out[:], key.PrivateKey)
	return out
}

// AsPublicKey returns only the private part of the key.
func (key *Key) AsPublicKey() *Key {
	if key.IsPublic() {
		return key
	}
	return &Key{
		ID:        OIDPublicKey,
		PublicKey: key.PublicKey,
	}
}

// Encrypt encrypts a message using a NaCL box to a public key
func (key *Key) Encrypt(message []byte, nonce *[24]byte, peer *Key) []byte {
	return box.Seal(nil, message, nonce, peer.BoxPublicKey(), key.BoxPrivateKey())
}

// Decrypt decrypts a NaCL box message from a public key
func (key *Key) Decrypt(in []byte, nonce *[24]byte, peer *Key) ([]byte, bool) {
	return box.Open(nil, in, nonce, peer.BoxPublicKey(), key.BoxPrivateKey())
}

// IsPrivate returns true if the key is a private key
func (key *Key) IsPrivate() bool {
	return key.ID.Equal(OIDPrivateKey) && len(key.PrivateKey) == keySize
}

// IsPublic returns true if the key is a public key
func (key *Key) IsPublic() bool {
	return key.ID.Equal(OIDPublicKey)
}

// Marshal converts the key to PEM format.
func (key *Key) Marshal() (out []byte, err error) {
	b := &pem.Block{}
	switch {
	case key.ID.Equal(OIDPrivateKey):
		b.Type = PEMPrivateKey
	case key.ID.Equal(OIDPublicKey):
		b.Type = PEMPublicKey
	default:
		return nil, errors.New("unknown identifier: " + key.ID.String())

	}
	b.Bytes, err = asn1.Marshal(*key)
	out = pem.EncodeToMemory(b)
	return
}

// Save writes the key to disk in PEM format.
func (key *Key) Save(file string) (err error) {
	var out []byte
	if out, err = key.Marshal(); err != nil {
		return err
	}
	return ioutil.WriteFile(file, out, os.FileMode(0600))
}

// NewPrivateKey generates a new NaCL box key pair.
func NewPrivateKey() (key *Key, err error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	key = &Key{
		ID:         OIDPrivateKey,
		PublicKey:  publicKey[:],
		PrivateKey: privateKey[:],
	}
	return key, nil
}

// Load loads a NaCL box key from PEM file.
func Load(file string) (*Key, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses any NaCL box key from a PEM blob.
func Parse(data []byte) (key *Key, err error) {
	var b *pem.Block
	for {
		b, data = pem.Decode(data)
		if b == nil || b.Type == PEMPublicKey || b.Type == PEMPrivateKey {
			break
		}
	}
	if b == nil {
		return nil, errors.New("no usable PEM block could be decoded")
	}
	key = new(Key)
	_, err = asn1.Unmarshal(b.Bytes, key)
	return key, err
}

// ParsePublicKey parses a NaCL box public key byte slice.
// TODO: error checking
func ParsePublicKey(data []byte) *Key {
	return &Key{
		ID:        OIDPublicKey,
		PublicKey: data,
	}
}

// LoadPrivateKey loads a NaCL box key pair PEM file.
func LoadPrivateKey(file string) (*Key, error) {
	key := new(Key)
	if err := LoadPEMBlock(file, PEMPrivateKey, key); err != nil {
		return nil, err
	}
	if !key.ID.Equal(OIDPrivateKey) {
		return nil, errors.New("not a secrets private key")
	}
	return key, nil
}

// LoadPublicKey loads a NaCL box public key PEM file.
func LoadPublicKey(file string) (*Key, error) {
	key := new(Key)
	if err := LoadPEMBlock(file, PEMPrivateKey, key); err != nil {
		return nil, err
	}
	if !key.ID.Equal(OIDPublicKey) {
		return nil, errors.New("not a secrets private key")
	}
	return key, nil
}

// LoadPEMBlock loads a PEM block from a file.
func LoadPEMBlock(file, kind string, v interface{}) (err error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	return ParsePEMBlock(data, kind, v)
}

// ParsePEMBlock parsea a PEM block from a byte slice.
func ParsePEMBlock(data []byte, kind string, v interface{}) (err error) {
	var b *pem.Block
	for {
		b, data = pem.Decode(data)
		if b == nil || b.Type == kind {
			break
		}
	}
	if b == nil {
		return fmt.Errorf("no %q PEM block could be decoded", kind)
	}
	_, err = asn1.Unmarshal(b.Bytes, v)
	return err
}
