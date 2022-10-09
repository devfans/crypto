package ecdsa

type Signer interface {
	// Sign message
	Sign(data []byte) (sig []byte, err error)

	// Verifier
	Verifier

	// Borrow verifier
	GetVerifier() Verifier

	FromKeyFile(file string) (err error)
	SaveKeyFile(file string) (err error)
	FromKeyStoreFile(file, pass string) (err error)
	SaveKeyStoreFile(file, pass string) (err error)
}

type Verifier interface {
	Verify(msg []byte, sig []byte) error
}