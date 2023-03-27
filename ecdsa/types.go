package ecdsa

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ECDSA
type Hash = common.Hash
type Address = common.Address
type PrivateKey = ecdsa.PrivateKey
type Publickey = ecdsa.PublicKey

var (
 	Keccak256 = crypto.Keccak256
 	Keccak256Hash = crypto.Keccak256Hash
	Ecrecover = crypto.Ecrecover

	Sign = crypto.Sign
	VerifySignature = crypto.VerifySignature
	S256 = crypto.S256

	DecompressPubkey = crypto.DecompressPubkey
	CompressPubkey = crypto.CompressPubkey
	PubkeyToAddress = crypto.PubkeyToAddress
	UnmarshalPubkey = crypto.UnmarshalPubkey
	FromECDSAPub = crypto.FromECDSAPub

	GenerateKey = crypto.GenerateKey
	FromECDSA = crypto.FromECDSA
	ToECDSA = crypto.ToECDSA


	BytesToAddress = common.BytesToAddress
)

func PubToAddress(pub []byte) Address {
	if len(pub) != 65 {
		panic("invalid pub key length")
	}
	return BytesToAddress(Keccak256(pub[1:])[12:])
}

func CompressedPubToAddress(pub []byte) (addr Address, err error) {
	p, err := DecompressPubkey(pub)
	if err != nil {
		return
	}
	return PubkeyToAddress(*p), nil
}

func DecodeSignature(sig []byte, chainID *big.Int) (r, s, v *big.Int) {
	if len(sig) != crypto.SignatureLength {
		panic(fmt.Sprintf("wrong size for signature: got %d, want %d", len(sig), crypto.SignatureLength))
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	if chainID != nil && chainID.Sign() != 0 {
		v = big.NewInt(int64(sig[64] + 35))
		v.Add(v, chainID).Add(v, chainID)
	}
	return r, s, v
}

func ComposeSignature(r, s, v, chainID *big.Int) (sig []byte) {
	sig = make([]byte, crypto.SignatureLength)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:64])
	if chainID == nil || chainID.Sign() == 0 {
		sig[64] = byte(v.Int64() - 27)
	} else {
		delta := new(big.Int).Sub(v, chainID)
		sig[64] = byte(delta.Sub(delta, chainID).Int64() - 35)
	}
	return
}
