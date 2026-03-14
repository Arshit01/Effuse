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
