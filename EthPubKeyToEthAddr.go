package main

import (
	"encoding/hex"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
)

func EthPubKeyToEthAddr(pubKey string) string {
	// Decode the public key from hex
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
	}

	// Generate the public key object
	publicKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		log.Fatalf("Failed to generate public key: %v", err)
	}

	// Generate the address
	address := crypto.PubkeyToAddress(*publicKey)
	return address.Hex()
}
