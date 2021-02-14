package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

/* AES CRT */
func AEC_CRT_Crypt(text []byte,key []byte) []byte{
	block,err:=aes.NewCipher(key)
	if err!=nil{
		panic(err)
	}
	count:=[]byte("12345678abcdefgh")
	blockMode:=cipher.NewCTR(block,count)
	message:=make([]byte,len(text))
	blockMode.XORKeyStream(message,text)
	return message
}

func main(){
	message:=[]byte("Hello!My name is X.")
	key:=[]byte("14725836qazwsxed")
	/* Encode */
	cipherText:=AEC_CRT_Crypt(message,key)
	fmt.Println("Encode：",len(string(cipherText)))

	/* Decode */
	plainText:=AEC_CRT_Crypt(cipherText,key)
	fmt.Println("Decode：",len(string(plainText)))
}
