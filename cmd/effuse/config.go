// Effuse - AES-256-GCM File Encryption Utility (v2)
// Copyright (C) 2025 Arshit Vora
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Arshit01/Effuse/internal/actions"
	"github.com/Arshit01/Effuse/internal/security"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

const (
	banner = `
███████╗███████╗███████╗██╗   ██╗███████╗███████╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔════╝██╔════╝
█████╗  █████╗  █████╗  ██║   ██║███████╗█████╗  
██╔══╝  ██╔══╝  ██╔══╝  ██║   ██║╚════██║██╔══╝  
███████╗██║     ██║     ╚██████╔╝███████║███████╗
╚══════╝╚═╝     ╚═╝      ╚═════╝ ╚══════╝╚══════╝
Effuse - AES-256-GCM File Encryption Utility 
`
	version = "v2.0.0"
	author  = "Arshit Vora"
	codename = "hac_king"
)

var (
	keyFile string
	outName string
	askOut  bool
	
	// Root Command
	rootCmd = &cobra.Command{
		Use:   "effuse",
		Short: "Effuse - AES-256-GCM File Encryption Utility",
		Long: pterm.DefaultCenter.WithCenterEachLineSeparately().Sprint(fmt.Sprintf("%s\n%s %s\n%s %s\n%s %s",
			pterm.NewRGB(0, 125, 156).Sprint(banner),
			pterm.LightYellow("Version:"), pterm.NewRGB(255, 23, 68).Sprint(version),
			pterm.LightYellow("Author:"), pterm.NewRGB(255, 23, 68).Sprint(author),
			pterm.LightYellow("Codename:"), pterm.NewRGB(255, 23, 68).Sprint(codename))),
		Run: func(cmd *cobra.Command, args []string) {
			// If no flags/subcommands, show help
			if len(args) == 0 {
				cmd.SetArgs([]string{"help"})
				cmd.Execute()
				return
			}
		},
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
)

func init() {
	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		pterm.Error.Println(err.Error())
		pterm.Info.Printf("Usage: effuse %s [flags] [files...]\n", cmd.Name())
		pterm.Info.Printf("Run 'effuse help %s' for more information.\n", cmd.Name())
		return nil
	})

	// Global persistent flags
	rootCmd.PersistentFlags().StringVar(&keyFile, "key", "", "Use PEM key file")
	rootCmd.PersistentFlags().StringVarP(&outName, "output", "o", "", "Output file name")
	rootCmd.PersistentFlags().BoolVar(&askOut, "out", false, "Prompt for output name for each file")

	// Hide the default help flag to focus on the 'help' subcommand
	rootCmd.PersistentFlags().BoolP("help", "h", false, "help for effuse")
	rootCmd.PersistentFlags().Lookup("help").Hidden = true

	// Subcommands
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(genKeyCmd)

	// Root Solution: Replace the default help footer with our preferred subcommand style
	rootCmd.SetUsageTemplate(strings.Replace(rootCmd.UsageTemplate(), "[command] --help", "help [command]", 1))
}

// encryptCmd for encrypt command
var encryptCmd = &cobra.Command{
	Use:     "encrypt [files...]",
	Aliases: []string{"e"},
	Short:   "Encrypt file(s)",
	Run: func(cmd *cobra.Command, args []string) {
		processFiles(args, "encrypt")
	},
}

// decryptCmd for decrypt command
var decryptCmd = &cobra.Command{
	Use:     "decrypt [files...]",
	Aliases: []string{"d"},
	Short:   "Decrypt file(s)",
	Run: func(cmd *cobra.Command, args []string) {
		processFiles(args, "decrypt")
	},
}

// infoCmd for info command
var infoCmd = &cobra.Command{
	Use:     "info [files...]",
	Aliases: []string{"i"},
	Short:   "Show file type info",
	Run: func(cmd *cobra.Command, args []string) {
		processFiles(args, "info")
	},
}

// genKeyCmd for genkey command
var genKeyCmd = &cobra.Command{
	Use:   "genkey [source_file]",
	Short: "Generate a new PEM key from a file",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			pterm.Error.Println("No source file specified for key generation.")
			pterm.Info.Println("Usage: effuse genkey [source_file]")
			pterm.Info.Println("Run 'effuse help genkey' for more information.")
			return
		}
		runGenKey(args[0])
	},
}

func runGenKey(source string) {
	// Check if source file exists
	if _, err := os.Stat(source); os.IsNotExist(err) {
		pterm.Error.Printf("Source file not found: %s\n", source)
		return
	}

	pterm.Info.Println("Generating RSA key from source:", source)
	
	// Ask for password for KDF master seed
	password, err := pterm.DefaultInteractiveTextInput.WithMask("*").Show("Enter password for key generation")
	if err != nil {
		return
	}
	
	// Generate dynamic PEM key output path
	outPath := outName
	if outPath == "" {
		timestamp := time.Now().Format("20060102-150405")
		idBytes := make([]byte, 2)
		rand.Read(idBytes)
		outPath = fmt.Sprintf("key-%s-%s.pem", timestamp, hex.EncodeToString(idBytes))
	} else if filepath.Ext(outPath) == "" {
		outPath += ".pem"
	}

	// Call deterministic key generation in security package
	if err := security.GenerateDeterministicRSAKeys(source, password, outPath); err != nil {
		pterm.Error.Println("Key generation failed:", err)
	}
}

func processFiles(files []string, mode string) {
	if len(files) == 0 {
		pterm.Error.Printf("No files specified for %s.\n", mode)
		pterm.Info.Printf("Usage: effuse %s [files...]\n", mode)
		pterm.Info.Printf("Run 'effuse help %s' for more information.\n", mode)
		return
	}

	// Check for file existence first
	var existingFiles []string
	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			existingFiles = append(existingFiles, file)
		} else {
			pterm.Warning.Printf("File not found '%s'. Skipping.\n", file)
		}
	}

	if len(existingFiles) == 0 {
		pterm.Error.Println("No valid files to process.")
		return
	}

	// Resolve Key/Password
	var passwordOrKey []byte
	var usePEM bool

	if keyFile != "" {
		k, err := security.GetKeyFromPEM(keyFile)
		if err != nil {
			pterm.Error.Println("Error reading key file:", err)
			os.Exit(1)
		}
		pterm.Info.Println("Using key from PEM file.")
		passwordOrKey = k
		usePEM = true
	} else {
		// Ask Password
		pw, _ := pterm.DefaultInteractiveTextInput.WithMask("*").Show("Enter password")
		if pw == "" {
			pterm.Error.Println("Password cannot be empty.")
			os.Exit(1)
		}
		
		if mode == "encrypt" {
			confirm, _ := pterm.DefaultInteractiveTextInput.WithMask("*").Show("Confirm password")
			if pw != confirm {
				pterm.Warning.Println("Passwords do not match.")
				os.Exit(1)
			}
		}
		passwordOrKey = []byte(pw)
		usePEM = false
	}

	// Info mode: collect results and display table
	if mode == "info" {
		tableData := pterm.TableData{
			{"File", "File Name", "Extension", "Version", "Status"},
		}

		for _, file := range existingFiles {
			info := actions.GetFileInfo(file, passwordOrKey, usePEM)
			tableData = append(tableData, []string{
				info.File, info.FileName, info.Extension, info.Version, info.Status,
			})
		}

		pterm.Println()
		pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(tableData).Render()
		return
	}

	// Encrypt/Decrypt mode
	for _, file := range existingFiles {
		var err error
		var currentOutPath string

		if mode == "encrypt" || mode == "decrypt" {
			if askOut {
				var promptErr error
				currentOutPath, promptErr = pterm.DefaultInteractiveTextInput.Show(fmt.Sprintf("Enter output name for %s", filepath.Base(file)))
				if promptErr != nil {
					pterm.Warning.Println("Input cancelled. Using default.")
				}
			} else if outName != "" {
				currentOutPath = outName
			}
		}

		switch mode {
		case "encrypt":
			err = actions.EncryptFile(file, passwordOrKey, usePEM, currentOutPath)
		case "decrypt":
			err = actions.DecryptFile(file, passwordOrKey, usePEM, currentOutPath)
		}
		if err != nil {
			// Only print errors not already displayed by the spinner
			var displayed *actions.DisplayedError
			if !errors.As(err, &displayed) {
				pterm.Error.Printf("Failed: %s - %v\n", file, err)
			}
		}
	}
}

