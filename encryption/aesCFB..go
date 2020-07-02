package encryption

import (
	"crypto/aes"
	"crypto/cipher"
)

type Cipher struct {
	block    cipher.Block
	Password []byte
}

func NewCipher(key []byte) *Cipher {
	block, _ := aes.NewCipher(key)
	return &Cipher{
		block,
		key,
	}
}
func (c *Cipher) AesEncrypt(ciphered, plaintext, iv []byte) {
	acesEncrypt := cipher.NewCFBEncrypter(c.block, iv)
	acesEncrypt.XORKeyStream(ciphered, plaintext)
}

func (c *Cipher) AesDecrypt(plaintext, ciphered, iv []byte) {
	absDecrypt := cipher.NewCFBDecrypter(c.block, iv)
	absDecrypt.XORKeyStream(plaintext, ciphered)
}
