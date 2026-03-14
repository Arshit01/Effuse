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

package actions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Append timestamp to prevent overwriting.
func generateSafePath(desiredPath string) string {
	if _, err := os.Stat(desiredPath); os.IsNotExist(err) {
		return desiredPath
	}

	ext := filepath.Ext(desiredPath)
	base := strings.TrimSuffix(desiredPath, ext)
	timestamp := time.Now().Format("20060102-150405")
	return fmt.Sprintf("%s-%s%s", base, timestamp, ext)
}

func ResolveOutputPath(srcPath, destDir, customFileName, originalName, finalExt string) string {
	var outDir string

	// Determine Output Directory
	if destDir != "" {
		// Strip trailing quotes
		destDir = strings.TrimSuffix(destDir, "\"")
		outDir = destDir
		// Ensure the custom directory exists
		os.MkdirAll(outDir, 0755)
	} else {
		// Default to source file's directory
		outDir = filepath.Dir(srcPath)
	}

	// Determine File Name
	var outName string
	if customFileName != "" {
		// Strip any trailing quotes
		outName = strings.TrimSuffix(customFileName, "\"")
	} else if originalName != "" {
		outName = originalName
	} else {
		outName = filepath.Base(srcPath)
		// Strip the original extension
		if finalExt == ".eff" {
			outName = strings.TrimSuffix(outName, filepath.Ext(outName))
		}
	}

	// Combine Directory and File Name
	desiredPath := filepath.Join(outDir, outName)

	// Force .eff Extension
	if finalExt == ".eff" {
		if !strings.HasSuffix(desiredPath, finalExt) {
			desiredPath += finalExt
		}
	} else if finalExt != "" {
		// Only append the MIME fallback extension if there is no extension
		if filepath.Ext(desiredPath) == "" {
			desiredPath += finalExt
		}
	}

	return generateSafePath(desiredPath)
}
