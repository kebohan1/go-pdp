package main

import (
	"fmt"
	"github.com/libp2p/go-openssl"
	"math/big"
)

func main() {
	privateKey := GenerateRSAKeyWithExponent(2048, 65535)

}
