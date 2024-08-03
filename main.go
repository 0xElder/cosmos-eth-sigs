package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
)

const priv_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" // testkey

// CompressPubKey compresses an ECDSA public key to the 33-byte compressed format
func CompressPubKey(pub *ecdsa.PublicKey) []byte {
	var compressedKey []byte
	if pub.Y.Bit(0) == 0 {
		compressedKey = append([]byte{0x02}, pub.X.Bytes()...)
	} else {
		compressedKey = append([]byte{0x03}, pub.X.Bytes()...)
	}
	return compressedKey
}

func privKeyToEthPubKey(privKey string) (string, error) {
	privateKey, err := crypto.HexToECDSA(privKey)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	return hex.EncodeToString(publicKeyBytes), nil
}

func privKeyToCosmosPubKey(privKey string) (string, error) {
	// Decode the private key from hex
	privateKeyBytes, err := hex.DecodeString(privKey)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
	}

	// Generate the private key object
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Generate the public key
	publicKeyBytes := privateKey.Public().(*ecdsa.PublicKey)

	compressedPubKey := CompressPubKey(publicKeyBytes)

	return fmt.Sprintf("%x", compressedPubKey), nil
}

func CosmosPubKeyToEthPubkey(pubKey string) (string, error) {
	// Decode the public key from hex
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
	}

	fmt.Println("pubKeyBytes", len(pubKeyBytes))
	// Generate the public key object
	publicKey, err := crypto.DecompressPubkey(pubKeyBytes)
	if err != nil {
		log.Fatalf("Failed to decompress public key: %v", err)
	}

	return hex.EncodeToString(crypto.FromECDSAPub(publicKey)), nil
}

func main() {
	pubKey, err := privKeyToEthPubKey(priv_key)
	if err != nil {
		log.Fatalf("Failed to convert private key to Ethereum public key: %v", err)
	}

	compressedPubKey, err := privKeyToCosmosPubKey(priv_key)
	if err != nil {
		log.Fatalf("Failed to convert private key to Cosmos public key: %v", err)
	}

	cosmosAddr := CosmosPublicKeyToCosmosAddress("cosmos", compressedPubKey)

	ethAddr := EthPubKeyToEthAddr(pubKey)

	ethPubKeyFromCosmosPubKey, err := CosmosPubKeyToEthPubkey(compressedPubKey)
	if err != nil {
		log.Fatalf("Failed to convert Ethereum public key to Cosmos public key: %v", err)
	}

	fmt.Printf("Ethereum public key from private key: 0x%s\n", pubKey)
	fmt.Printf("Cosmos public key from private key: %s\n", compressedPubKey)
	fmt.Printf("Cosmos address from cosmos public key: %s\n", cosmosAddr)
	fmt.Printf("Ethereum address from Ethereum public key: %s\n", ethAddr)
	fmt.Printf("Ethereum public key from Cosmos public key: %s\n", ethPubKeyFromCosmosPubKey)
}
