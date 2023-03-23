package ecdsa

import (
	"fmt"
	"math/big"
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

func decodeSignature(sig []byte) (r, s, v *big.Int) {
	if len(sig) != crypto.SignatureLength {
		panic(fmt.Sprintf("wrong size for signature: got %d, want %d", len(sig), crypto.SignatureLength))
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v
}

func TestApply(t *testing.T) {
	pri, _ := crypto.HexToECDSA(os.Getenv("KEY"))
	signer := NewSigner(pri)
	hash := common.HexToHash("ca3cd6ca6f6c8e96f466588b08a8e38e902c112380eebf8eaa95576341448874")
	sig, err := signer.Sign(hash.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	decode := func(sig []byte) (R, S, V *big.Int, err error) {
		chain := big.NewInt(0)
		R, S, V = decodeSignature(sig)
		if chain.Sign() != 0 {
			V = big.NewInt(int64(sig[64] + 35))
			V.Add(V, chain)
		}
		return R, S, V, nil
	}
	r, s, v, _ := decode(sig)
	fmt.Printf("0x%x 0x%x 0x%x", v.Bytes(), r.Bytes(), s.Bytes())
}
