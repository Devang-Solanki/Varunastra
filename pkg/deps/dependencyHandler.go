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
)

// HandleDependencyFile processes and checks a specific dependency file
func HandleDependencyFile(fileName string, tr *tar.Reader) ([]VulnIssue, error) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, tr); err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", fileName, err)
	}
	content := buf.Bytes()

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
