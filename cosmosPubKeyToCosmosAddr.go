package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"

	bech32 "github.com/btcsuite/btcutil/bech32"
	"golang.org/x/crypto/ripemd160"
)

// PublicKeyToAddress converts secp256k1 public key to a bech32 Tendermint/Cosmos based address
func CosmosPublicKeyToCosmosAddress(addressPrefix, publicKeyString string) string {
	// Decode public key string
	pubKeyBytes, err := hex.DecodeString(publicKeyString)
	if err != nil {
		log.Fatalf("Failed to decode public key hex: %v", err)
	}

	// Hash pubKeyBytes as: RIPEMD160(SHA256(public_key_bytes))
	pubKeySha256Hash := sha256.Sum256(pubKeyBytes)
	ripemd160hash := ripemd160.New()
	ripemd160hash.Write(pubKeySha256Hash[:])
	addressBytes := ripemd160hash.Sum(nil)

	// Convert addressBytes into a bech32 string
	address := toBech32(addressPrefix, addressBytes)

	return address
}

// Code courtesy: https://github.com/cosmos/cosmos-sdk/blob/90c9c9a9eb4676d05d3f4b89d9a907bd3db8194f/types/bech32/bech32.go#L10
func toBech32(addrPrefix string, addrBytes []byte) string {
	converted, err := bech32.ConvertBits(addrBytes, 8, 5, true)
	if err != nil {
		panic(err)
	}

	addr, err := bech32.Encode(addrPrefix, converted)
	if err != nil {
		panic(err)
	}

	return addr
}
