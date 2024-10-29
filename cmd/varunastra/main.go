package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Devang-Solanki/Varunastra/pkg/config"
	"github.com/Devang-Solanki/Varunastra/pkg/docker"

	"github.com/alecthomas/kong"
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

// handleScan processes the scan command.
func handleScan(cli config.CLI, regexDB []config.RegexDB, excludedPatterns config.ExcludedPatterns) {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <docker-image>", os.Args[0])
	}

	scanMap := config.CreateScanMap(cli.Scans)

	imageName := cli.Target

	// Process each image
	output, err := docker.ProcessImage(imageName, scanMap, regexDB, excludedPatterns)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Scanning completed.")

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))
}

func main() {

	var cli config.CLI
	ctx := kong.Parse(&cli)

	// Process scans
	scanMap := make(map[string]bool)
	defaultScans := []string{"secrets", "vuln", "assets"}

	if cli.Scans == "" {
		for _, scan := range defaultScans {
			scanMap[scan] = true
		}
	} else {
		scanList := strings.Split(cli.Scans, ",")
		for _, scan := range defaultScans {
			scanMap[scan] = false // Default to false
		}
		for _, scan := range scanList {
			scanMap[scan] = true // Set specified scans to true
		}
	}

	regexDB, excludedPatterns, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Process the command based on the context
	handleScan(cli, regexDB, excludedPatterns)
	ctx.Exit(0)
}
