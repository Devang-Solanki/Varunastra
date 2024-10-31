package deps

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/Devang-Solanki/go-ruby-bundler-audit/rubyaudit"
)

// checkNPMDependencyVulnerabilities checks for known vulnerabilities in an NPM dependency
func checkDependencyVulnerabilities(dep Dependency, filename string, env string) error {
	// Clean the version string
	cleanedVersion := cleanVersion(dep)

	// Encode the package name for the API request
	encodedName := url.PathEscape(dep.Name)

	// Construct the API URL
	apiURL := fmt.Sprintf("https://api.deps.dev/v3/systems/%s/packages/%s/versions/%s", env, encodedName, cleanedVersion.Version)

	// Perform the HTTP GET request
	resp, err := http.Get(apiURL)
	if err != nil {
		log.Printf("Failed to fetch vulnerabilities for %s@%s: %v", dep.Name, dep.Version, err)
		return err
	}
	defer resp.Body.Close()

	// Check if the response status is not 200 (OK)
	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to fetch vulnerabilities for %s@%s: HTTP status %d", dep.Name, dep.Version, resp.StatusCode)
		return fmt.Errorf("HTTP status %d for %s@%s", resp.StatusCode, dep.Name, dep.Version)
	}

	var response struct {
		AdvisoryKeys []struct {
			ID string `json:"id"`
		} `json:"advisories"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		log.Printf("Failed to parse vulnerabilities for %s@%s: %v", dep.Name, dep.Version, err)
		return err
	}

	// Log the found vulnerabilities
	if len(response.AdvisoryKeys) != 0 {
		for _, advisory := range response.AdvisoryKeys {
			// Fetch and log detailed information about each advisory
			details, err := getAdvisoryDetails(advisory.ID)
			if err != nil {
				log.Printf("Failed to fetch details for advisory %s: %v", advisory.ID, err)
				continue
			}
			addDepenDencyIssueDetails(details, filename, dep, "NPM")
		}
	}

	return nil
}

// checkNPMDependencyConfusion checks for potential dependency confusion for an NPM dependency
func checkNPMDependencyConfusion(dep Dependency) error {
	// Query the public NPM registry to get information about the package
	apiURL := fmt.Sprintf("https://registry.npmjs.org/%s", url.PathEscape(dep.Name))

	resp, err := http.Get(apiURL)
	if err != nil {
		log.Printf("Failed to fetch package info for %s: %v", dep.Name, err)
		return err
	}
	defer resp.Body.Close()

	// Check if the response status is 404 (Not Found) indicating the package does not exist on NPM
	if resp.StatusCode == http.StatusNotFound {
		log.Printf("Package %s does not exist on the public NPM registry.", dep.Name)
		addDepenDencyIssueDetails(dep.Name, apiURL, dep, "NPM")
		return nil
	}

	return nil
}

// checkGemDependencyVulnerabilities checks for known vulnerabilities in a Gem dependency.
func checkGemDependencyVulnerabilities(dep rubyaudit.Dependency, filename string) error {
	result, err := rubyaudit.SearchAdvisories(dep.Name, dep.Version)
	if err != nil {
		log.Printf("Error searching advisories: %v, %s:%s", err, dep.Name, dep.Version)
		return err
	}

	addDepenDencyIssueDetails(result, filename, dep, "GEM")
	return nil
}

// checkGemDependencyConfusion checks for potential dependency confusion for a Gem dependency.
func checkGemDependencyConfusion(dep rubyaudit.Dependency) error {
	log.Printf("Checking dependency confusion for Gem dependency: %s@%s", dep.Name, dep.Version)

	apiURL := fmt.Sprintf("https://rubygems.org/gems/%s", dep.Name)
	// Implement logic to check for dependency confusion, e.g., checking if the dependency exists in a public registry.

	resp, err := http.Get(apiURL)
	if err != nil {
		log.Printf("Failed to fetch package info for %s: %v", dep.Name, err)
		return err
	}
	defer resp.Body.Close()

	// Check if the response status is 404 (Not Found) indicating the package does not exist on NPM
	if resp.StatusCode == http.StatusNotFound {
		log.Printf("Package %s does not exist on the public NPM registry.", dep.Name)
		addDepenDencyIssueDetails(dep.Name, apiURL, dep, "NPM")
		return nil
	}
	return nil
}
