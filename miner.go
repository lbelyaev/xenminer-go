package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"log"
	rnd "math/rand"
	"runtime"
	"strings"
	"sync"
	"time"
)

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func generateArgonHash(password string, p *params) (string, error) {
	// Generate a cryptographically secure random salt.
	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		log.Println("Error generating random ", err)
		return "", err
	}

	// Pass the plaintext password, salt and parameters to the argon2.IDKey
	// function. This will generate a hash of the password using the Argon2id
	// variant.
	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return a string using the standard encoded hash representation.
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memory, p.iterations, p.parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{};:,.<>?"

func generateRandomSHA256(maxLength int) string {
	rnd.Seed(time.Now().UnixNano())
	randomString := make([]byte, rnd.Intn(maxLength)+1)
	for i := range randomString {
		randomString[i] = characters[rnd.Intn(len(characters))]
	}

	sha256Hash := sha256.Sum256(randomString)
	return fmt.Sprintf("%x", sha256Hash)
}

func main() {
	p := &params{
		memory:      64 * 1024,
		iterations:  1,
		parallelism: 1,
		saltLength:  16,
		keyLength:   128,
	}

	var count int
	interval := 1 * time.Second // Measurement interval

	go func() {
		for {
			<-time.After(interval) // Wait for the interval to elapse
			rate := float64(count) / interval.Seconds()
			fmt.Printf("Rate per second: %.2f\n", rate)
			count = 0 // Reset the count for the next interval
		}
	}()

	mine := func() {
		for {
			hash := generateRandomSHA256(128)
			hashedData, _ := generateArgonHash(hash, p)
			if strings.Contains(hashedData, "XEN11") {
				log.Println(hashedData)
			}
			count += 1
		}
	}

	numCpu := runtime.NumCPU()

	var wg sync.WaitGroup

	for i := 0; i < numCpu; i++ {
		go mine()
		wg.Add(1)
	}

	wg.Wait()

}
