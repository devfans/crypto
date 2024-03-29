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

	Decrypt(data, s1, s2 []byte) (msg []byte, err error)
	Encrypt(pub, msg, s1, s2 []byte) (data []byte, err error)
}

type Verifier interface {
	Verify(msg []byte, sig []byte) error
}