package key

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
)

func TestGenerate(t *testing.T) {
	_, err := NewPrivateKey()
	if err != nil {
		t.Error(err)
	}
}

func TestMarshal(t *testing.T) {
	temp, err := ioutil.TempFile("", "secrets-key")
	if err != nil {
		t.Error(err)
		return
	}

	want, err := NewPrivateKey()
	if err != nil {
		t.Error(err)
		return
	}

	if err = want.Save(temp.Name()); err != nil {
		t.Error(err)
		return
	}
	defer os.Remove(temp.Name())

	test, err := Load(temp.Name())
	if err != nil {
		t.Error(err)
		return
	}

	if !bytes.Equal(test.PublicKey, want.PublicKey) {
		t.Error("wrong public key after load")
		return
	}
	if !bytes.Equal(test.PrivateKey, want.PrivateKey) {
		t.Error("wrong private key after load")
		return
	}

	wantBytes, err := want.Marshal()
	if err != nil {
		t.Error(err)
		return
	}
	testBytes, err := test.Marshal()
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(wantBytes, testBytes) {
		t.Error("marshal inconsistencies")
		return
	}
}
