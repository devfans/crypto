package bls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/devfans/crypto/bls/blst"
	ec "github.com/devfans/crypto/ecdsa"
	"github.com/devfans/crypto/bls/common"
	"github.com/stretchr/testify/assert"
)


func TestSigner(t *testing.T) {

	data := []byte("data to be signed")
	hash := ec.Keccak256Hash(data)

	key, err := ecdsa.GenerateKey(ec.S256(), rand.Reader)
	assert.NoError(t, err, "failed to generate key")
	sig, err := ec.Sign(hash.Bytes(), key)
	assert.NoError(t, err, "failed to sign data")
	t.Logf("ecdsa pri key %x size %d", ec.FromECDSA(key), len(ec.FromECDSA(key)) )
	t.Logf("ecdsa pub key %x size %d", ec.FromECDSAPub(&key.PublicKey), len(ec.FromECDSAPub(&key.PublicKey)) )
	t.Logf("ecdsa compressed pub key %x size %d", ec.CompressPubkey(&key.PublicKey), len(ec.CompressPubkey(&key.PublicKey)) )
	t.Logf("ecdsa sig %x, size %d", sig, len(sig))


	priv, err := RandKey()
	assert.NoError(t, err)
	blsSig := priv.Sign(hash.Bytes())
	t.Logf("bls pri key %x size %d", priv.Marshal(), len(priv.Marshal()) )
	t.Logf("bls pub key %x size %d", priv.PublicKey().Marshal(), len(priv.PublicKey().Marshal()) )
	t.Logf("bls sig %x, size %d", blsSig.Marshal(), len(blsSig.Marshal()))
	assert.True(t, blst.VerifyCompressed(blsSig.Marshal(), priv.PublicKey().Marshal(), hash.Bytes()))


	priv2, err := RandKey()
	assert.NoError(t, err)
	blsSig2 := priv2.Sign(hash.Bytes())
	assert.True(t, blst.VerifyCompressed(blsSig2.Marshal(), priv2.PublicKey().Marshal(), hash.Bytes()))

	
	aggPub := AggregateMultiplePubkeys([]common.PublicKey{priv.PublicKey(), priv2.PublicKey()})
	aggSig := AggregateSignatures([]common.Signature{blsSig, blsSig2})
	assert.True(t, blst.VerifyCompressed(aggSig.Marshal(), aggPub.Marshal(), hash.Bytes()))

	t.Logf("agg pub key %x size %d", aggPub.Marshal(), len(aggPub.Marshal()) )
	t.Logf("agg sig %x, size %d", aggSig.Marshal(), len(aggSig.Marshal()))
}