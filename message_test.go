package main

import (
	"bytes"
	"testing"

	"github.com/tehmaze-labs/secrets/key"
	"golang.org/x/crypto/nacl/secretbox"
)

var text = `They're taking the hobbits to Isengard!
They're taking the hobbits to Isengard!
They're taking the hobbits to Isengard!
They're taking the hobbits to Isengard!
They're taking the hobbits to Isengard!
They're taking the hobbits to Isengard!
They're taking the hobbits to Isengard!

What did you say?

The hobbits
The hobbits
The hobbits
The hobbits

To Isengard!
To Isengard!

The hobbits
The hobbits
The hobbits
The hobbits
`

func TestSecret(t *testing.T) {
	sKey, err := key.NewPrivateKey()
	if err != nil {
		t.Error(err)
		return
	}
	rKeys := []*key.Key{}
	rPubs := []*key.Key{}
	for i := 0; i < 8; i++ {
		rKey, err := key.NewPrivateKey()
		if err != nil {
			t.Error(err)
			return
		}
		rKeys = append(rKeys, rKey)
		rPubs = append(rPubs, rKey.AsPublicKey())
	}

	message := []byte(text)
	for i, secret := range NewGroupSecret(message, sKey, rPubs) {
		out, err := secret.Marshal()
		if err != nil {
			t.Error(err)
			return
		}
		//fmt.Fprintf(os.Stderr, string(out))
		if len(message) < secretbox.Overhead {
			t.Errorf("%d bytes message smaller than overhead %d", len(message), secretbox.Overhead)
			return
		}

		output, err := secret.Decrypt(rKeys[i])
		if err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(output, message) {
			t.Error("corrupt")
			return
		}
		//t.Logf("good, got %q", string(output))
	}
}
