package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"

	"github.com/tehmaze-labs/secrets/key"
	"golang.org/x/crypto/nacl/secretbox"
)

// Secret is an encrypted message, ready to be sent over the network.
type Secret struct {
	Key     []byte `json:"key"`
	Sender  []byte `json:"sender"`
	Nonce   []byte `json:"nonce"`
	Secret  []byte `json:"secret"`
	Message []byte `json:"message"`
}

// Decrypt decrypts the message for recipient
func (s *Secret) Decrypt(r *key.Key) ([]byte, error) {
	if !bytes.Equal(s.Key, r.BoxPublicKey()[:]) {
		return nil, errors.New("invalid key")
	}

	nonce := [24]byte{}
	copy(nonce[:], s.Nonce)

	// First get the message encryption key
	key, ok := r.Decrypt(s.Secret, &nonce, key.ParsePublicKey(s.Sender))
	if !ok {
		return nil, errors.New("unable to open box key")
	}
	if len(key) != 32 {
		return nil, errors.New("invalid secret box key size")
	}

	// Next unlock the secret box
	skey := [32]byte{}
	copy(skey[:], key)
	message, ok := secretbox.Open(nil, s.Message, &nonce, &skey)
	if !ok {
		return nil, errors.New("unable to open secret box")
	}
	return message, nil
}

// Marshal returns the JSON encoded secret.
func (s *Secret) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

// NewGroupSecret sends an encrypted copy of message to all the recipients. The
// secret is encrypted using sender's private key and recipient's public key.
func NewGroupSecret(message []byte, sender *key.Key, keys []*key.Key) []Secret {
	secrets := []Secret{}
	// Generate a unique box nonce
	nonce := [24]byte{}
	io.ReadFull(rand.Reader, nonce[:])
	// Generate a message encryption key
	key := new([32]byte)
	io.ReadFull(rand.Reader, key[:])

	// Encrypt the message to each recipient
	for _, recipient := range keys {
		rKey := sender.Encrypt(key[:], &nonce, recipient)
		secrets = append(secrets, Secret{
			Key:     recipient.BoxPublicKey()[:],
			Sender:  sender.BoxPublicKey()[:],
			Nonce:   nonce[:],
			Secret:  rKey,
			Message: secretbox.Seal(nil, message, &nonce, key),
		})
	}
	//*/
	/*
		nonce := [24]byte{}
		io.ReadFull(rand.Reader, nonce[:])
		for _, recipient := range keys {
			secrets = append(secrets, Secret{
				Key:     recipient.BoxPublicKey()[:],
				Nonce:   nonce[:],
				Message: sender.Encrypt(message, &nonce, recipient),
			})
		}
	*/
	return secrets
}
