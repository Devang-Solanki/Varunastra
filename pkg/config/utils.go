package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/Devang-Solanki/Varunastra/config"
	"github.com/Devang-Solanki/Varunastra/pkg/docker"
)

func HandleOutput(output []docker.FinalOutput, cli config.CLI) {

	if cli.Output == "" {
		data, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(data))
	} else {
		if err := writeOutputToFile(cli, output); err != nil {
			log.Fatalln("Error:", err)
		}
	}

}

func writeOutputToFile(cli config.CLI, output interface{}) error {
	if cli.Output == "" {
		return fmt.Errorf("no output filename specified")
	}

	// Marshal the output data to JSON with indentation
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output: %v", err)
	}

	// Open the file for writing (this will overwrite the file if it exists)
	file, err := os.Create(cli.Output) // Use os.OpenFile if you want to append instead
	if err != nil {
		return fmt.Errorf("failed to create or open file %s: %v", cli.Output, err)
	}
	defer file.Close()

	// Write the data to the file
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write data to file %s: %v", cli.Output, err)
	}

	return nil
}
