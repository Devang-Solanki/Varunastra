package docker

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/Devang-Solanki/Varunastra/pkg/config"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"mvdan.cc/xurls/v2"
)

// AddDomainsAndUrls appends new domains and URLs to assets
func (a *Assets) AddDomainsAndUrls(content string) {
	domains := GetSubdomainsAndDomains(content)
	a.Domains = append(a.Domains, domains...)

	urls := GetUrls(content)
	a.Urls = append(a.Urls, urls...)

}

// MakeUniqueDomains removes duplicate domains and subdomains
func (a *Assets) MakeUniqueDomains() {
	uniqueDomains := make(map[string]map[string]struct{})

	for _, domain := range a.Domains {
		if _, exists := uniqueDomains[domain.Domain]; !exists {
			uniqueDomains[domain.Domain] = make(map[string]struct{})
		}
		for _, sub := range domain.Subdomains {
			uniqueDomains[domain.Domain][sub] = struct{}{}
		}
	}

	a.Domains = make([]SubAndDom, 0, len(uniqueDomains))
	for domainName, subdomainSet := range uniqueDomains {
		subdomains := make([]string, 0, len(subdomainSet))
		for sub := range subdomainSet {
			subdomains = append(subdomains, sub)
		}
		a.Domains = append(a.Domains, SubAndDom{Domain: domainName, Subdomains: subdomains})
	}
}

// MakeUniqueUrls removes duplicate URLs
func (a *Assets) MakeUniqueUrls() {
	uniqueUrls := make(map[string]struct{})
	for _, url := range a.Urls {
		uniqueUrls[url] = struct{}{}
	}

	a.Urls = make([]string, 0, len(uniqueUrls))
	for url := range uniqueUrls {
		a.Urls = append(a.Urls, url)
	}
}

func GetUrls(content string) []string {
	rxStrict := xurls.Strict()
	urls := rxStrict.FindAllString(content, -1) // []string{"http://foo.com/"}
	return urls
}

func GetSubdomainsAndDomains(content string) []SubAndDom {
	pattern := `[A-Za-z0-9](?:[A-Za-z0-9.-]){2,63}\.[A-Za-z0-9]{2,18}`
	regex := regexp.MustCompile(pattern)

	subdomains := regex.FindAllString(content, -1)

	domainMap := make(map[string][]string)

	for _, subdomain := range subdomains {
		domain, _ := publicsuffix.DomainFromListWithOptions(
			publicsuffix.DefaultList,
			subdomain,
			&publicsuffix.FindOptions{
				IgnorePrivate: true,
			},
		)

		domain = strings.ToLower(domain)
		subdomain = strings.ToLower(subdomain)

		if domain != "" && subdomain != domain {
			domainMap[domain] = append(domainMap[domain], subdomain)
		}
	}

	var filteredDomains []SubAndDom
	for domain, subdomains := range domainMap {
		data := SubAndDom{Domain: domain, Subdomains: subdomains}
		filteredDomains = append(filteredDomains, data)
	}

	return filteredDomains
}

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
