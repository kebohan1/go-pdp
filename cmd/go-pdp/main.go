package main

import (
	"crypto/rand"
	rsa "crypto/rsa"
	"fmt"
)

func main() {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for i := 0; i < len(privateKey.Primes); i++ {
		fmt.Printf("private key %s", privateKey.Primes[i])
	}

	// fmt.Printf("%s", publicKey)

}
