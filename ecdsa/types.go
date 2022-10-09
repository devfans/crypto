package ecdsa

import (
	"crypto/ecdsa"

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

