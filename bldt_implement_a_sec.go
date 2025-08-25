package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/boltdb/bolt"
)

type Message struct {
	Text string `json:"text"`
}

type SecureChatbot struct {
	db *bolt.DB
}

func NewSecureChatbot(dbFile string) (*SecureChatbot, error) {
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		return nil, err
	}
	return &SecureChatbot{db: db}, nil
}

func (sc *SecureChatbot) parseInput(input string) ([]byte, error) {
	key := []byte("my_secret_key")
	ciphertext, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (sc *SecureChatbot) handleMessage(input string) ([]byte, error) {
	plaintext, err := sc.parseInput(input)
	if err != nil {
		return nil, err
	}
	var msg Message
	err = json.Unmarshal(plaintext, &msg)
	if err != nil {
		return nil, err
	}
	log.Printf("Received message: %s\n", msg.Text)
	return []byte(msg.Text), nil
}

func main() {
	sc, err := NewSecureChatbot("secure_chatbot.db")
	if err != nil {
		log.Fatal(err)
	}
	defer sc.db.Close()

	fmt.Println("Secure Chatbot Parser started!")
	fmt.Println("Enter encrypted message (base64 encoded):")
	var input string
	fmt.Scanln(&input)
	response, err := sc.handleMessage(input)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Response:", string(response))
}