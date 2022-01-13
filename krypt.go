package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
)

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func main() {
	encAction := flag.String("action", "str", "a string")
	encPass := flag.String("passw", "str", "a string")
	encFilename := flag.String("filename", "str", "a string")
	flag.Parse()
	//fileName := "priv_esc.jpeg"
	data, err := ioutil.ReadFile(*encFilename)
	if err != nil {
		fmt.Println("File reading error", err)
	}

	if *encAction == "encrypt" {
		encr := encrypt(data, *encPass)
		ioutil.WriteFile(*encFilename, encr, 0777)
	} else if *encAction == "decrypt" {
		decr := decrypt(data, *encPass)
		ioutil.WriteFile(*encFilename, decr, 0777)
	} else {
		fmt.Printf("Flags\n-action=encrypt/decrypt\n-passw=somePassHere\n-filename=fileNameHere")
	}

}
