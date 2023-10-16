package main

import (
	"crypto/rand"
	// "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/minio/sha256-simd"
	// "golang.org/x/crypto/argon2"
	"github.com/tvdburgt/go-argon2"
	"io"
	"log"
	rnd "math/rand"
	"net/http"
	"runtime"
	"strconv"
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

func generateArgonHash(password string, salt []byte, p *params) (string, error) {
	// Generate a cryptographically secure random salt.

	// Pass the plaintext password, salt and parameters to the argon2.IDKey
	// function. This will generate a hash of the password using the Argon2id
	// variant.
	// hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	ctx := &argon2.Context{
		Iterations:  1,
		Memory:      int(p.memory),
		Parallelism: 1,
		HashLen:     int(p.keyLength),
		Mode:        argon2.ModeArgon2id,
		Version:     argon2.Version13,
	}
	hash, err := argon2.Hash(ctx, []byte(password), salt)
	if err != nil {
		log.Fatal(err)
	}

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return a string using the standard encoded hash representation.
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version13, p.memory, p.iterations, p.parallelism, b64Salt, b64Hash)

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

func getDifficulty(url string) uint {
	res, err := http.Get(url)
	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
		return 0
	} else {
		reqBody, err := io.ReadAll(res.Body)
		if err != nil {
			fmt.Printf("error decoding http request: %s\n", err)
		}
		var blocks XenBlocks
		err = json.Unmarshal(reqBody, &blocks)
		if err != nil {
			fmt.Printf("error decoding json: %s\n", err)
		}
		i, err := strconv.Atoi(blocks.Difficulty)
		if err != nil {
			fmt.Printf("error decoding json: %s\n", err)
		}
		return uint(i)
	}
}

type XenBlocks struct {
	Difficulty string `json:"difficulty"`
}

func main() {

	threads := flag.Uint64("threads", uint64(runtime.NumCPU()), "no of threads")
	flag.Parse()

	log.Printf("Using %d threads\n", *threads)

	diff := getDifficulty("http://xenblocks.io/difficulty")
	log.Printf("Diff: %d\n", diff)

	p := &params{
		memory:      uint32(diff),
		iterations:  1,
		parallelism: 1,
		saltLength:  16,
		keyLength:   128,
	}

	var count int
	interval := 1 * time.Second // Measurement interval

	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		log.Println("Error generating random ", err)
	}

	go func() {
		for {
			<-time.After(interval) // Wait for the interval to elapse
			rate := float64(count) / interval.Seconds()
			fmt.Printf("\rRate per second: %.2f", rate)
			count = 0 // Reset the count for the next interval
		}
	}()

	mine := func() {
		for {
			hash := generateRandomSHA256(128)
			hashedData, _ := generateArgonHash(hash, salt, p)
			if strings.Contains(hashedData[len(hashedData)-87:], "XEN11") {
				log.Println(hashedData)
			}
			count += 1
		}
	}

	getDiff := func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		quit := make(chan struct{})

		for {
			select {
			case <-t.C:
				diff = getDifficulty("http://xenblocks.io/difficulty")
				log.Printf("Diff: %d\n", diff)

			case <-quit:
				t.Stop()
				return
			}
		}
	}

	var wg sync.WaitGroup
	var i uint64

	for i = 0; i < *threads; i++ {
		go mine()
		wg.Add(1)
	}

	go getDiff()
	wg.Add(1)

	wg.Wait()

}
