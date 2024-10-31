<p align="center">
  <a href="https://cyclic.sh/">
    <img src="https://devanghacks.in/varunastra/croped_logo.png" alt="cyclic.sh" width="200">
  </a>
  <br>
</p>
<p align="center">
<a href="https://www.gnu.org/licenses/gpl-3.0.en.html/"><img src="https://img.shields.io/badge/license-GPL_3.0-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/Devang-Solanki/Varunastra"><img src="https://goreportcard.com/badge/github.com/Devang-Solanki/Varunastra"></a>
<a href="https://go.dev/blog/go1.22.5"><img src="https://img.shields.io/github/go-mod/go-version/Devang-Solanki/Varunastra"></a>
<a href="https://twitter.com/devangsolankii"><img src="https://img.shields.io/twitter/follow/devangsolankii.svg?logo=twitter"></a>
</p>
<!-- <p align="center">
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-todo">Todo</a> •
  <a href="#-how-to-contribute">Contribute</a> 
</p> -->


## Varunastra: Securing the Depths of Docker

Introducing Varunastra, an innovative tool designed to enhance the security of Docker environments. Named after The Varunastra (वरुणास्त्र), it is the water weapon according to the Indian scriptures, incepted by Varuna, god of hydrosphere. Varunastra is engineered to detect and help mitigate vulnerabilities in Docker, ensuring robust security across all Docker containers and images.

## Key Features

- **Secret Scanning:** Reduces the risk of sensitive data leaks.
- **Asset Extraction:** Retrieves assets such as domain/subdomains and urls from Docker images for bug bounty hunters.
- **Customizable Solution:** Define regex patterns and blacklists to meet specific needs.
- **Dependency Checks:** Automates assessments for quicker threat identification.

**Supported Lock Files**
| Language   | File                |
|------------|---------------------|
| Ruby       | Gemfile.lock        |
| Javascript | package-lock.json   |
|            | yarn.lock           |


### Usage

```bash
❯ varunastra -h
Usage: varunastra --target=STRING [flags]

Flags:
  -h, --help             Show context-sensitive help.
      --target=STRING    Target string
      --scans=STRING     Comma-separated scans (secrets,vuln,assets)
```


#### Example 

```bash
 varunastra --target trufflesecurity/secrets --scans "secrets,vuln,assets"
```

```
2024/10/20 21:32:03 Checking if config file exist
2024/10/20 21:32:03 Starting Scan for Image: trufflesecurity/secrets
2024/10/20 21:32:05 Scanning Layers: sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59
2024/10/20 21:32:05
2024/10/20 21:32:05 Secrets found -> Type: Amazon AWS Access Key ID | Secret: AKIAXYZDQCEN4B6JSJQI | On Path: aws
2024/10/20 21:32:05
2024/10/20 21:32:05 Secrets found -> Type: AWS API Key | Secret: AKIAXYZDQCEN4B6JSJQI | On Path: aws
2024/10/20 21:32:05 Scanning completed.
{
  "target": "trufflesecurity/secrets",
  "secrets": [
    {
      "issue": "Secret Leaked in Docker Layer sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59",
      "asset": "aws",
      "type": "Amazon AWS Access Key ID",
      "secret": "AKIAXYZDQCEN4B6JSJQI"
    },
    {
      "issue": "Secret Leaked in Docker Layer sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59",
      "asset": "aws",
      "type": "AWS API Key",
      "secret": "AKIAXYZDQCEN4B6JSJQI"
    }
  ],
  "vulnerabilities": null
}
```

<a href="https://www.buymeacoffee.com/devangsolankii" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174" /></a>
