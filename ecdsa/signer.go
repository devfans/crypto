package ecdsa

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

type ECDSASigner struct {
	key *PrivateKey
}

func (s *ECDSASigner) Sign(msg []byte) (sig []byte, err error) {
	return crypto.Sign(msg, s.key)
}

func (s *ECDSASigner) GetVerifier() Verifier {
	return NewPubkeyVerifier(&s.key.PublicKey)
}

func (s *ECDSASigner) Verify(msg []byte, sig []byte) (err error) {
	return s.GetVerifier().Verify(msg, sig)
}

func (s *ECDSASigner) FromKeyStoreFile(file, pass string) (err error) {
	s.key, err = FromKeyStoreFile(file, pass)
	return
}

func (s *ECDSASigner) SaveKeyStoreFile(file, pass string) (err error) {
	return SaveKeyStoreFile(file, pass, s.key)
}

func (s *ECDSASigner) FromKeyFile(file string) (err error) {
	s.key, err = FromKeyFile(file)
	return
}

func (s *ECDSASigner) SaveKeyFile(file string) (err error) {
	return SaveKeyFile(file, s.key)
}

func NewSigner(key *PrivateKey) Signer {
	return &ECDSASigner{key}
}

type AddressVerifier struct {
	addr Address
}

func NewAddressVerifier(addr Address) Verifier {
	return &AddressVerifier{addr}
}

func (v *AddressVerifier) Verify(msg []byte, sig []byte) (err error) {
	pub, err := Ecrecover(msg, sig)
	if err != nil {
		return
	}
	if bytes.Equal(PubToAddress(pub).Bytes(), v.addr.Bytes()) {
		return nil
	}
	return errors.New("signer verify failure")
}

type PubkeyVerifier struct {
	pub *Publickey
}

func NewPubkeyVerifier(pub *Publickey) Verifier {
	return &PubkeyVerifier{pub}
}

func (v *PubkeyVerifier) Verify(msg []byte, sig []byte) (err error) {
	pub, err := Ecrecover(msg, sig)
	if err != nil {
		return
	}
	if bytes.Equal(pub, FromECDSAPub(v.pub)) {
		return nil
	}
	return errors.New("signer verify failure")
}

func VerifySigWithAddress(msg, sig []byte, address Address) (err error) {
	pub, err := Ecrecover(msg, sig)
	if err != nil {
		return
	}
	if bytes.Equal(PubToAddress(pub).Bytes(), address.Bytes()) {
		return nil
	}
	return errors.New("signer verify failure")
}

func VerifySigWithPubKey(msg, sig, pub []byte) (err error) {
	p, err := Ecrecover(msg, sig)
	if err != nil {
		return
	}
	if bytes.Equal(p, pub) {
		return nil
	}
	return errors.New("signer verify failure")
}

func FromKeyStoreFile(path, pass string) (pri *PrivateKey, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	key, err := keystore.DecryptKey(data, pass)
	if err != nil { return }
	pri = key.PrivateKey
	return
}

func SaveKeyStore(dir, pass string, pri *PrivateKey) (err error) {
	ks := keystore.NewKeyStore(dir, keystore.StandardScryptN, keystore.StandardScryptP)
	_, err = ks.ImportECDSA(pri, pass)
	return
}

func SaveKeyStoreFile(file, pass string, pri *PrivateKey) (err error) {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Could not create random uuid: %v", err))
	}
	key := &keystore.Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(pri.PublicKey),
		PrivateKey: pri,
	}
	data, err := keystore.EncryptKey(key, pass, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		return err
	}
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		// os.Remove(f.Name())
		return err
	}
	f.Close()
	return nil
}

var (
	FromKeyFile = crypto.LoadECDSA
	SaveKeyFile = crypto.SaveECDSA
)