package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"

	pkcs7 "github.com/mergermarket/go-pkcs7"
)

func Encrypt(fileName string) (map[string][]byte, error) {
	var resultMap map[string][]byte
	unencrypted, err := ioutil.ReadFile(fileName)
	if err != nil {
		return resultMap, err
	}
	resultMap = make(map[string][]byte)
	key := make([]byte, 32)
	rand.Read(key)
	plainText := unencrypted
	plainText, err = pkcs7.Pad(plainText, aes.BlockSize)
	if err != nil {
		return resultMap, err
	}
	if len(plainText)%aes.BlockSize != 0 {
		err := fmt.Errorf(`plainText: "%s" has the wrong block size`, plainText)
		return resultMap, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return resultMap, err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return resultMap, err

	}

	mode := cipher.NewCBCEncrypter(block, iv)

	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	resultMap["key"] = key
	resultMap["encrypted"] = cipherText

	return resultMap, nil
}

func Decrypt(encFile string, keyFile string) ([]byte, error) {
	/*
		fencFile, _ := ioutil.ReadFile(encFile)
		enc := []byte(fencFile)
		fkeyFile, _ := ioutil.ReadFile(keyFile)
		key := []byte(fkeyFile)
	*/
	enc := []byte(encFile)
	key := []byte(keyFile)
	cipherText, _ := hex.DecodeString(string(enc))
	fmt.Println(len(enc))
	fmt.Println(len(key))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(cipherText) < aes.BlockSize {
		panic("cipherText too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	if len(cipherText)%aes.BlockSize != 0 {
		panic("cipherText is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	cipherText, _ = pkcs7.Unpad(cipherText, aes.BlockSize)
	return cipherText, nil
}

func main() {
	encryptedFile, err := Encrypt("ddos-nzok.txt")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(encryptedFile)
	decryptedFile, err := Decrypt(string(encryptedFile["encrypted"]), string(encryptedFile["key"]))
	fmt.Println(decryptedFile)
	//ioutil.WriteFile("ddos-nzok.txt.enc", encryptedFile["encrypted"], 0777)
	//ioutil.WriteFile("key.enc", encryptedFile["key"], 0777)
}
