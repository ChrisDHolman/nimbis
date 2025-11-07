package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ScannerInstaller handles automatic installation of scanners
type ScannerInstaller struct {
	cacheDir string
}

// NewScannerInstaller creates a new installer
func NewScannerInstaller() (*ScannerInstaller, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	cacheDir := filepath.Join(homeDir, ".nimbis", "scanners")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}

	return &ScannerInstaller{
		cacheDir: cacheDir,
	}, nil
}

// InstallAll installs all available scanners
func (i *ScannerInstaller) InstallAll() error {
	fmt.Println("🔧 Auto-installing security scanners...")
	fmt.Println("   This may take a few minutes on first run...")
	
	scanners := []struct {
		name    string
		install func() error
	}{
		{"Trivy", i.installTrivy},
		{"TruffleHog", i.installTruffleHog},
		{"Grype", i.installGrype},
		{"Syft", i.installSyft},
		// Note: Checkov requires Python/pip, OpenGrep requires npm
		// These are skipped in auto-install but user can install manually
	}

	installed := 0
	for _, scanner := range scanners {
		fmt.Printf("   Installing %s...", scanner.name)
		if err := scanner.install(); err != nil {
			fmt.Printf(" ⚠️  failed: %v\n", err)
			continue
		}
		fmt.Println(" ✓")
		installed++
	}

	if installed == 0 {
		return fmt.Errorf("failed to install any scanners")
	}

	fmt.Printf("\n✅ Installed %d/%d scanners successfully\n", installed, len(scanners))
	fmt.Println("\n💡 To install additional scanners manually:")
	fmt.Println("   • Checkov: pip3 install checkov")
	fmt.Println("   • OpenGrep: npm install -g @opengrep/cli")
	fmt.Println()
	
	// Add to PATH for current session
	currentPath := os.Getenv("PATH")
	if !strings.Contains(currentPath, i.cacheDir) {
		os.Setenv("PATH", i.cacheDir+string(os.PathListSeparator)+currentPath)
	}
	
	return nil
}

// installTrivy installs Trivy scanner
func (i *ScannerInstaller) installTrivy() error {
	binaryName := "trivy"
	if runtime.GOOS == "windows" {
		binaryName = "trivy.exe"
	}

	binaryPath := filepath.Join(i.cacheDir, binaryName)
	if _, err := os.Stat(binaryPath); err == nil {
		return nil // Already installed
	}

	version := "0.67.2" // Updated to latest version
	owner := "aquasecurity"
	repo := "trivy"
	tag := "v" + version

	// Build correct filter based on OS
	var filters []string
	if runtime.GOOS == "windows" {
		filters = []string{"windows", "64bit", ".zip"}
	} else {
		// For Linux/macOS, the format is: trivy_0.67.2_Linux-64bit.tar.gz
		filters = []string{runtime.GOOS, ".tar.gz"}
		
		// Add architecture filter
		if runtime.GOARCH == "amd64" {
			filters = append(filters, "64bit")
		} else if runtime.GOARCH == "arm64" {
			filters = append(filters, "ARM64")
		} else if runtime.GOARCH == "arm" {
			filters = append(filters, "ARM64")
		}
	}

	assetURL, err := i.getGitHubAssetURL(owner, repo, tag, filters)
	if err != nil {
		return err
	}

	return i.downloadAndExtract(assetURL, binaryName, binaryPath)
}

// installTruffleHog installs TruffleHog scanner
func (i *ScannerInstaller) installTruffleHog() error {
	binaryName := "trufflehog"
	if runtime.GOOS == "windows" {
		binaryName = "trufflehog.exe"
	}

	binaryPath := filepath.Join(i.cacheDir, binaryName)
	if _, err := os.Stat(binaryPath); err == nil {
		return nil
	}

	version := "3.82.13"
	var url string

	switch runtime.GOOS {
	case "linux":
		url = fmt.Sprintf("https://github.com/trufflesecurity/trufflehog/releases/download/v%s/trufflehog_%s_linux_%s.tar.gz",
			version, version, runtime.GOARCH)
	case "darwin":
		url = fmt.Sprintf("https://github.com/trufflesecurity/trufflehog/releases/download/v%s/trufflehog_%s_darwin_%s.tar.gz",
			version, version, runtime.GOARCH)
	case "windows":
		url = fmt.Sprintf("https://github.com/trufflesecurity/trufflehog/releases/download/v%s/trufflehog_%s_windows_%s.zip",
			version, version, runtime.GOARCH)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	return i.downloadAndExtract(url, binaryName, binaryPath)
}

// installGrype installs Grype scanner
func (i *ScannerInstaller) installGrype() error {
	binaryName := "grype"
	if runtime.GOOS == "windows" {
		binaryName = "grype.exe"
	}

	binaryPath := filepath.Join(i.cacheDir, binaryName)
	if _, err := os.Stat(binaryPath); err == nil {
		return nil
	}

	version := "0.84.0"
	var url string

	switch runtime.GOOS {
	case "linux":
		url = fmt.Sprintf("https://github.com/anchore/grype/releases/download/v%s/grype_%s_linux_%s.tar.gz",
			version, version, runtime.GOARCH)
	case "darwin":
		url = fmt.Sprintf("https://github.com/anchore/grype/releases/download/v%s/grype_%s_darwin_%s.tar.gz",
			version, version, runtime.GOARCH)
	case "windows":
		url = fmt.Sprintf("https://github.com/anchore/grype/releases/download/v%s/grype_%s_windows_%s.zip",
			version, version, runtime.GOARCH)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	return i.downloadAndExtract(url, binaryName, binaryPath)
}

// installSyft installs Syft scanner
func (i *ScannerInstaller) installSyft() error {
	binaryName := "syft"
	if runtime.GOOS == "windows" {
		binaryName = "syft.exe"
	}

	binaryPath := filepath.Join(i.cacheDir, binaryName)
	if _, err := os.Stat(binaryPath); err == nil {
		return nil
	}

	version := "1.17.0"
	var url string

	switch runtime.GOOS {
	case "linux":
		url = fmt.Sprintf("https://github.com/anchore/syft/releases/download/v%s/syft_%s_linux_%s.tar.gz",
			version, version, runtime.GOARCH)
	case "darwin":
		url = fmt.Sprintf("https://github.com/anchore/syft/releases/download/v%s/syft_%s_darwin_%s.tar.gz",
			version, version, runtime.GOARCH)
	case "windows":
		url = fmt.Sprintf("https://github.com/anchore/syft/releases/download/v%s/syft_%s_windows_%s.zip",
			version, version, runtime.GOARCH)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	return i.downloadAndExtract(url, binaryName, binaryPath)
}

// downloadAndExtract downloads and extracts a binary
func (i *ScannerInstaller) downloadAndExtract(url, binaryName, binaryPath string) error {
	// Download to temp file
	tempFile := filepath.Join(os.TempDir(), filepath.Base(url))
	
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	out, err := os.Create(tempFile)
	if err != nil {
		return err
	}
	defer out.Close()
	defer os.Remove(tempFile)

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	out.Close()

	// Extract based on file type
	if strings.HasSuffix(url, ".tar.gz") {
		return i.extractTarGz(tempFile, binaryName, binaryPath)
	} else if strings.HasSuffix(url, ".zip") {
		return i.extractZip(tempFile, binaryName, binaryPath)
	}

	return fmt.Errorf("unsupported archive format")
}

// extractTarGz extracts a tar.gz file
func (i *ScannerInstaller) extractTarGz(archivePath, binaryName, binaryPath string) error {
	// Use tar command
	cmd := exec.Command("tar", "-xzf", archivePath, "-C", i.cacheDir, binaryName)
	if err := cmd.Run(); err != nil {
		return err
	}

	// Make executable
	if runtime.GOOS != "windows" {
		if err := os.Chmod(binaryPath, 0755); err != nil {
			return err
		}
	}

	return nil
}

// extractZip extracts a zip file
func (i *ScannerInstaller) extractZip(archivePath, binaryName, binaryPath string) error {
	// Use unzip command
	cmd := exec.Command("unzip", "-o", archivePath, binaryName, "-d", i.cacheDir)
	if err := cmd.Run(); err != nil {
		return err
	}

	// Make executable
	if runtime.GOOS != "windows" {
		if err := os.Chmod(binaryPath, 0755); err != nil {
			return err
		}
	}

	return nil
}

// AddToPath adds the cache directory to PATH permanently
func (i *ScannerInstaller) AddToPath() {
	currentPath := os.Getenv("PATH")
	if !strings.Contains(currentPath, i.cacheDir) {
		os.Setenv("PATH", i.cacheDir+string(os.PathListSeparator)+currentPath)
	}
}

// GetCacheDir returns the cache directory
func (i *ScannerInstaller) GetCacheDir() string {
	return i.cacheDir
}
