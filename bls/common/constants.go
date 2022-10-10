package common

// ZeroSecretKey represents a zero secret key.
var ZeroSecretKey = [32]byte{}

// InfinitePublicKey represents an infinite public key (G1 Point at Infinity).
var InfinitePublicKey = [BLSPubkeyLength]byte{0xC0}

// InfiniteSignature represents an infinite signature (G2 Point at Infinity).
var InfiniteSignature = [96]byte{0xC0}

const (
	BLSSignatureLength              = 96            // BLSSignatureLength defines the byte length of a BLSSignature.
	BLSPubkeyLength                 = 48  
	RootLength                      = 32            // RootLength defines the byte length of a Merkle root.
	BLSSecretKeyLength              = 32
)
