package deps

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/Devang-Solanki/go-ruby-bundler-audit/rubyaudit"
)

var (
	issues []VulnIssue
	seen   map[string]bool
)

// InitializeSeenMap ensures the seen map is initialized
func initializeSeenMap() {
	if seen == nil {
		seen = make(map[string]bool)
	}
}

// MarkFileAsSeen marks the specified file as processed
func markFileAsSeen(fileName string) {
	initializeSeenMap()
	seen[fileName] = true
}

// HandleDependencyFile processes and checks a specific dependency file
func HandleDependencyFile(fileName string, tr *tar.Reader) ([]VulnIssue, error) {

	initializeSeenMap()

	// Check if the file has already been seen
	if seen[fileName] {
		return nil, fmt.Errorf("we have seen %s already", fileName)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, tr); err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", fileName, err)
	}
	content := buf.Bytes()

	markFileAsSeen(fileName) // Mark the file as seen

	switch {
	case strings.HasSuffix(fileName, "package-lock.json"):
		if err := handlePackageLockJSON(fileName, &content); err != nil {
			return nil, err
		}
	case strings.HasSuffix(fileName, "Gemfile.lock"):
		if err := handleGemLockfile(fileName, &content); err != nil {
			return nil, err
		}
	case strings.HasSuffix(fileName, "yarn.lock"):
		if err := handleYarnLockDependencies(fileName, &content); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported dependency file type: %s", fileName)
	}

	return issues, nil
}

// handlePackageLockJSON processes a package-lock.json file to check for vulnerabilities and dependency confusion
func handlePackageLockJSON(fileName string, content *[]byte) error {
	if strings.Contains(fileName, "node_modules") {
		return fmt.Errorf("skipping package-lock.json file in node_modules: %s", fileName)
	}

	log.Printf("Processing: %s", fileName)

	var data map[string]interface{}
	if err := json.Unmarshal(*content, &data); err != nil {
		return fmt.Errorf("failed to parse %s: %v", fileName, err)
	}

	dependencies := extractPackageLockDependencies(data)
	log.Printf("Found %d dependencies in %s", len(dependencies), fileName)

	// Check each dependency for vulnerabilities and dependency confusion
	var allErrors []error // Collect all errors

	for _, dep := range dependencies {
		err := checkDependencyVulnerabilities(dep, fileName, "npm")
		if err != nil {
			// Log the error and continue with the next dependency
			allErrors = append(allErrors, err)
			continue // Skip to the next dependency
		}

		err = checkNPMDependencyConfusion(dep)
		if err != nil {
			// Log the error and continue with the next dependency
			allErrors = append(allErrors, err)
			continue // Skip to the next dependency
		}
	}

	// After the loop, you can handle the collected errors if needed
	if len(allErrors) > 0 {
		// You could return a summary of errors or handle them as needed
		return fmt.Errorf("encountered errors while processing dependencies: %v", allErrors)
	}

	return nil
}

func handleYarnLockDependencies(fileName string, content *[]byte) error {
	if strings.Contains(fileName, "node_modules") {
		return fmt.Errorf("skipping yarn.lock file in node_modules: %s", fileName)
	}

	log.Printf("Processing: %s", fileName)

	dependencies := extractYarnLockDependencies(content)
	log.Printf("Found %d dependencies in %s", len(dependencies), fileName)

	// Check each dependency for vulnerabilities and dependency confusion
	for _, dep := range dependencies {
		err := checkDependencyVulnerabilities(dep, fileName, "npm")
		if err != nil {
			return err
		}
		err = checkNPMDependencyConfusion(dep)
		if err != nil {
			return err
		}
	}

	return nil
}

// handleGemLockfile processes a Gemfile.lock to check for vulnerabilities and dependency confusion.
func handleGemLockfile(fileName string, content *[]byte) error {
	log.Printf("Handling Gemfile.lock: %s", fileName)

	dependencies := rubyaudit.ExtractGemfileLockDependenciesRaw(content)
	log.Printf("Found %d dependencies in %s", len(dependencies), fileName)

	// Check each dependency for vulnerabilities and dependency confusion.
	for _, dep := range dependencies {
		err := checkGemDependencyVulnerabilities(dep, fileName)
		if err != nil {
			return err
		}
		// checkGemDependencyConfusion(dep)
	}

	return nil
}
