package ecdsa

import (
	"os"
	"testing"
)

func TestECDSA(t *testing.T) {
	pri, err := GenerateKey()
	if err != nil { t.Fatal(err) }

	signer := NewSigner(pri)

	data := "test"
	msg := Keccak256Hash([]byte(data))

	sig, err := signer.Sign(msg.Bytes())
	if err != nil { t.Fatal(err) }

	err = signer.Verify(msg.Bytes(), sig)
	if err != nil { t.Fatal(err) }

	verifier := NewAddressVerifier(PubkeyToAddress(pri.PublicKey))
	err = verifier.Verify(msg.Bytes(), sig)
	if err != nil { t.Fatal(err) }

	file := "test.json"
	err = SaveKeyFile(file, pri)
	if err != nil { t.Fatal(err) }
	pri, err = FromKeyFile(file)
	if err != nil { t.Fatal(err) }
	err = VerifySigWithPubKey(msg.Bytes(), sig, FromECDSAPub(&pri.PublicKey))
	if err != nil { t.Fatal(err) }

	err = os.Remove(file)
	if err != nil { t.Fatal(err) }

	pass := "test"
	err = SaveKeyStoreFile(file, pass, pri)
	if err != nil { t.Fatal(err) }
	pri, err = FromKeyStoreFile(file, pass)
	if err != nil { t.Fatal(err) }
	err = VerifySigWithPubKey(msg.Bytes(), sig, FromECDSAPub(&pri.PublicKey))
	if err != nil { t.Fatal(err) }
	err = os.Remove(file)
	if err != nil { t.Fatal(err) }
}