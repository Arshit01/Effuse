#!/bin/bash

# Update dependencies
echo "Running go mod tidy..."
go mod tidy

# Create dist directories
mkdir -p dist/linux/{amd64,arm64}
mkdir -p dist/darwin/{amd64,arm64}
mkdir -p dist/windows/{amd64,arm64}

echo "Building binaries..."

# Linux
echo "Building for Linux (amd64)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/linux/amd64/effuse ./cmd/effuse
echo "Building for Linux (arm64)..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/linux/arm64/effuse ./cmd/effuse

# macOS
echo "Building for macOS (amd64)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/darwin/amd64/effuse ./cmd/effuse
echo "Building for macOS (arm64)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/darwin/arm64/effuse ./cmd/effuse

# Windows
echo "Building for Windows (amd64)..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/windows/amd64/effuse.exe ./cmd/effuse
echo "Building for Windows (arm64)..."
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/windows/arm64/effuse.exe ./cmd/effuse

echo "Build complete! Artifacts are in the 'dist' directory."
