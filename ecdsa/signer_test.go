package ecdsa

import (
	"fmt"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestECDSA(t *testing.T) {
	pri, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	signer := NewSigner(pri)

	data := "test"
	msg := Keccak256Hash([]byte(data))

	sig, err := signer.Sign(msg.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	err = signer.Verify(msg.Bytes(), sig)
	if err != nil {
		t.Fatal(err)
	}

	verifier := NewAddressVerifier(PubkeyToAddress(pri.PublicKey))
	err = verifier.Verify(msg.Bytes(), sig)
	if err != nil {
		t.Fatal(err)
	}

	file := "test.json"
	err = SaveKeyFile(file, pri)
	if err != nil {
		t.Fatal(err)
	}
	pri, err = FromKeyFile(file)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifySigWithPubKey(msg.Bytes(), sig, FromECDSAPub(&pri.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	err = os.Remove(file)
	if err != nil {
		t.Fatal(err)
	}

	pass := "test"
	err = SaveKeyStoreFile(file, pass, pri)
	if err != nil {
		t.Fatal(err)
	}
	pri, err = FromKeyStoreFile(file, pass)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifySigWithPubKey(msg.Bytes(), sig, FromECDSAPub(&pri.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	err = os.Remove(file)
	if err != nil {
		t.Fatal(err)
	}
}

func TestApply(t *testing.T) {
	pri, _ := crypto.HexToECDSA(os.Getenv("KEY"))
	signer := NewSigner(pri)
	hash := common.HexToHash("04048961f7045c60b01cb6801c7869d22183d0cba75411fa04880cfaa6fd76de")
	sig, err := signer.Sign(hash.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	r, s, v := DecodeSignature(sig, nil)
	fmt.Printf("0x%x 0x%x 0x%x", v.Bytes(), r.Bytes(), s.Bytes())
}
