package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// func GenerateCustomID() string {
// 	currentTime := time.Now().UnixNano()
// 	randomNumber, _ := rand.Int(rand.Reader, big.NewInt(1000000))
// 	return fmt.Sprintf("%d-%d", currentTime, randomNumber)
// }

func Init() {
	// Read the JSON file
	data, err := os.ReadFile(REGEXFILE)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Unmarshal JSON data into a map

	if err := json.Unmarshal(data, &regexes); err != nil {
		log.Fatalf("Error unmarshalling JSON: %v", err)
	}

	var regexDB RegexDB
	var dbs []RegexDB

	for title, pattern := range regexes {

		regexDB.ID = title
		regexDB.Pattern = regexp.MustCompile(pattern)

		dbs = append(dbs, regexDB)
	}

	regexStore = dbs
}

func checkDupEntry(secret, typestr string, path string, finalResult []SecretIssue) bool {
	for _, dxresult := range finalResult {
		// log.Println(strings.Trim(strings.Trim(dxresult.Secret, "`"), "\""), secret)
		if dxresult.Type == typestr && strings.Trim(strings.Trim(dxresult.Secret, "`"), "\"") == secret && dxresult.Path == path {
			// if dxresult.Type == typestr && dxresult.Secret == secret {
			return true
		}
	}
	return false
}

// secretScanner scans the content for secrets and returns any issues found
func secretScanner(path string, content *[]byte, id interface{}) ([]SecretIssue, error) {
	var finalResult []SecretIssue
	var place string

	switch v := id.(type) {
	case v1.Hash:
		id = v.String()
		place = "Layer"
	case string:
		id = v
		place = "History"
	default:
		return nil, fmt.Errorf("unsupported type: %T", id)
	}

	for _, regex := range regexStore {
		x := regex.Pattern.FindAllSubmatch(*content, -1)
		if len(x) > 0 {
			for _, y := range x {
				if len(y) > 1 && regex.ID != "" {
					if checkDupEntry(string(y[1]), regex.ID, path, finalResult) {
						continue
					}
				}
				var kissue SecretIssue
				kissue.Issue = fmt.Sprintf("Secret Leaked in Docker %s %s", place, id)
				kissue.Path = path
				kissue.Type = regex.ID
				kissue.Secret = string(y[0])

				finalResult = append(finalResult, kissue)

				log.Print("\n")
				log.Printf("Secrets found -> Type: %s | Secret: %s | On Path: %s", regex.ID, string(y[0]), path)
			}
		}
	}

	if len(finalResult) != 0 {
		return finalResult, nil
	}

	return nil, fmt.Errorf("no secrets found in %s", id)
}