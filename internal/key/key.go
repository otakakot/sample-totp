package key

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

type CommonKey []byte

func GenerateECDH() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func EncodeECDHPublicKey(
	key *ecdh.PublicKey,
) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("x509.MarshalPKIXPublicKey: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), nil
}

func DecodeECDHPublicKey(
	key []byte,
) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("pem.Decode: block is nil")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("pem.Decode: block.Type is not PUBLIC KEY")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	}

	pub, ok := parsed.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: parsed is not *ecdh.PublicKey")
	}

	return pub, nil
}

func Encrypt(
	key []byte,
	text []byte,
) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	b := base64.StdEncoding.EncodeToString(text)

	cipt := make([]byte, aes.BlockSize+len(b))

	iv := cipt[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)

	cfb.XORKeyStream(cipt[aes.BlockSize:], []byte(b))

	return base64.StdEncoding.EncodeToString(cipt), nil
}

func Decrypt(
	key []byte,
	cip string,
) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	text, err := base64.StdEncoding.DecodeString(cip)
	if err != nil {
		return nil, err
	}

	if len(text) < aes.BlockSize {
		return nil, errors.New("too short")
	}

	iv := text[:aes.BlockSize]

	text = text[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)

	cfb.XORKeyStream(text, text)

	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}

	return data, nil
}
