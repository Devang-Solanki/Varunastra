package docker

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/Devang-Solanki/Varunastra/pkg/config"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// fetchTagsFromDockerHub fetches available tags for an image from Docker Hub
func fetchTagsFromDockerHub(imageName string) ([]string, error) {
	repo := strings.Split(imageName, ":")[0]
	repoParts := strings.Split(repo, "/")

	// Formulate the Docker Hub API URL
	var apiURL string
	if len(repoParts) == 1 {
		// For official Docker Hub images
		apiURL = fmt.Sprintf("https://registry.hub.docker.com/v2/repositories/library/%s/tags", repo)
	} else {
		// For other Docker Hub images
		apiURL = fmt.Sprintf("https://registry.hub.docker.com/v2/repositories/%s/%s/tags", repoParts[0], repoParts[1])
	}

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tags: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch tags: received status %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var tagsResponse struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &tagsResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	tags := make([]string, 0, len(tagsResponse.Results))
	for _, result := range tagsResponse.Results {
		tags = append(tags, result.Name)
	}

	return tags, nil
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
func secretScanner(path string, content *[]byte, id interface{}, regexDB []config.RegexDB) ([]SecretIssue, error) {
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

	for _, regex := range regexDB {
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
