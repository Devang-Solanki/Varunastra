package docker

import (
	"archive/tar"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"

	"github.com/Devang-Solanki/Varunastra/pkg/config"
	"github.com/Devang-Solanki/Varunastra/pkg/deps"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

var (
	scans config.ScanMap
)

type ScanWorker struct {
	scanMap   map[string]bool
	regexDB   []config.RegexDB
	output    *FinalOutput
	imageName string
}

// ProcessImage scans a Docker image for vulnerabilities.
func ProcessImage(imageName string, scanMap map[string]bool, regexDB []config.RegexDB, excludedPatterns config.ExcludedPatterns, allTagsScan bool) ([]FinalOutput, error) {
	scans = scanMap
	var combinedOutput []FinalOutput
	log.Println("Starting Scan for Image:", imageName)

	isLocalFile := strings.HasSuffix(imageName, ".tar")

	var _ v1.Image
	var err error

	if isLocalFile {
		_, err = tarball.ImageFromPath(imageName, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to load local image %s: %v", imageName, err)
		}
	} else {
		combinedOutput, err = processImage(imageName, scanMap, regexDB, excludedPatterns, allTagsScan)
		if err != nil {
			return nil, err
		}
	}

	return combinedOutput, nil
}

// processRemoteImage scans all tags of a remote Docker image.
func processImage(imageName string, scanMap map[string]bool, regexDB []config.RegexDB, excludedPatterns config.ExcludedPatterns, allTagsScan bool) ([]FinalOutput, error) {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %s: %v", imageName, err)
	}

	tags, err := fetchTagsFromRegistry(imageName, ref.Context().Registry)
	if err != nil || len(tags) == 0 {
		return nil, fmt.Errorf("failed to fetch tags or no tags found for image %s: %v", imageName, err)
	}

	var combinedOutput []FinalOutput
	for _, tag := range tags {
		output, err := scanImageTag(imageName, tag, scanMap, regexDB, excludedPatterns)
		if err != nil {
			return nil, err
		}
		combinedOutput = append(combinedOutput, output)
		if !allTagsScan {
			break
		}
	}
	return combinedOutput, nil
}

// scanImageTag scans a specific image tag for vulnerabilities.
func scanImageTag(imageName, tag string, scanMap map[string]bool, regexDB []config.RegexDB, excludedPatterns config.ExcludedPatterns) (FinalOutput, error) {
	taggedImage := fmt.Sprintf("%s:%s", strings.Split(imageName, ":")[0], tag)
	ref, err := name.ParseReference(taggedImage)
	if err != nil {
		return FinalOutput{}, fmt.Errorf("failed to parse image reference %s: %v", taggedImage, err)
	}

	img, err := remote.Image(ref)
	if err != nil {
		return FinalOutput{}, fmt.Errorf("failed to retrieve remote image %s: %v", taggedImage, err)
	}

	output := FinalOutput{Target: taggedImage}
	errs := launchWorkerPool(img, taggedImage, excludedPatterns, scanMap, regexDB, &output)
	if len(errs) > 0 {
		return output, fmt.Errorf("error(s) during scan: %v", errs)
	}

	return output, nil
}

// launchWorkerPool starts a pool of workers to scan layers and environment history concurrently.
func launchWorkerPool(img v1.Image, name string, excludedPatterns config.ExcludedPatterns, scanMap map[string]bool, regexDB []config.RegexDB, output *FinalOutput) []error {
	var wg sync.WaitGroup
	errorCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := processLayers(img, excludedPatterns, output, name); err != nil {
			errorCh <- fmt.Errorf("error processing layers: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := processHistoryAndENV(img, name); err != nil {
			errorCh <- fmt.Errorf("error scanning environment variables: %w", err)
		}
	}()

	wg.Wait()
	close(errorCh)

	var errs []error
	for err := range errorCh {
		errs = append(errs, err)
	}
	return errs
}

// processLayers scans each layer of an image.
func processLayers(img v1.Image, excludedPatterns config.ExcludedPatterns, output *FinalOutput, imagName string) error {
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("failed to get image layers: %w", err)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxGoroutines)

	for _, layer := range layers {
		key, err := getLayerInfo(layer)
		if err != nil {
			return fmt.Errorf("error getting layer hash: %w", err)
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(layer v1.Layer, key v1.Hash) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := processLayer(layer, key, excludedPatterns, imagName, output); err != nil {
				log.Printf("error processing layer: %s", err)
			}
		}(layer, key)
	}

	wg.Wait()
	return nil
}

// processLayer scans an individual layer of an image.
func processLayer(layer v1.Layer, digest v1.Hash, excludedPatterns config.ExcludedPatterns, imageName string, output *FinalOutput) error {
	log.Println("Scanning Layer:", digest.String())
	r, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("failed to get uncompressed layer: %w", err)
	}
	defer r.Close()

	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || isExcluded(header.Name, excludedPatterns) {
			continue
		}
		err = processFileContent(tr, header, digest, imageName, output)
		if err != nil {
			log.Printf("Error processing file %s: %s", header.Name, err)
		}
	}
	return nil
}

// processFileContent scans the content of a file in a layer.
func processFileContent(tr *tar.Reader, header *tar.Header, digest v1.Hash, imageName string, output *FinalOutput) error {

	// Scan the file content for secrets
	// Check if it's a known dependency file
	if scans["vuln"] && deps.IsKnownDependencyFile(header.Name) {
		vulnData, err := deps.HandleDependencyFile(header.Name, tr)
		if err != nil && !(strings.Contains(err.Error(), "unsupported dependency file type") || strings.Contains(err.Error(), "we have seen")) {
			log.Println(err)
		}

		if len(vulnData) > 0 {
			output.Vulnerability = append(output.Vulnerability, vulnData...)
		}
	}

	if header.Size > maxFileSize {
		// Handle large files by writing to a temp file
		return processLargeFile(tr, header.Name, digest, imageName)
	} else {
		// Handle smaller files directly
		return processSmallFile(tr, header.Name, digest, imageName)
	}
}

// processHistoryAndENV scans the history and environment variables for secrets.
func processHistoryAndENV(img v1.Image, image string) error {
	config, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("failed to get image config: %w", err)
	}
	for i, entry := range config.History {
		if entry.CreatedBy != "" {
			createdByContent := []byte(entry.CreatedBy)
			queueTask(fmt.Sprintf("history:%d", i), &createdByContent, fmt.Sprintf("history:%d", i), image)
		}
	}
	for _, envVar := range config.Config.Env {
		envVarContent := []byte(envVar)
		queueTask("ENV", &envVarContent, config.RootFS.DiffIDs[0], image)
	}
	return nil
}
