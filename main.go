package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	version = "0.2.1"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "nimbis",
		Short: "Nimbis - Multi-Scanner Security Analysis Tool",
		Long: `
███    ██ ██ ███    ███ ██████  ██ ███████ 
████   ██ ██ ████  ████ ██   ██ ██ ██      
██ ██  ██ ██ ██ ████ ██ ██████  ██ ███████ 
██  ██ ██ ██ ██  ██  ██ ██   ██ ██      ██ 
██   ████ ██ ██      ██ ██████  ██ ███████ 
                v` + version + `
    IaC • Secrets • SAST • SCA • SBOM

Nimbis orchestrates multiple open-source security scanners
to provide comprehensive security analysis for your projects.
`,
		Run: func(cmd *cobra.Command, args []string) {
			// Show welcome screen on first run or when no flags provided
			showWelcomeScreen()
		},
	}

	var scanCmd = &cobra.Command{
		Use:   "scan [path]",
		Short: "Run security scans on a directory or file",
		Long: `Run comprehensive security scans using multiple scanners.

Examples:
  nimbis scan .                    # Scan current directory
  nimbis scan /path/to/project     # Scan specific directory
  nimbis scan --scanners trivy-vuln,grype  # Use specific scanners
  nimbis scan --severity CRITICAL  # Only show critical issues`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runScan(cmd, args)
		},
	}

	var setupCmd = &cobra.Command{
		Use:   "setup",
		Short: "Install and configure security scanners",
		Long: `Install security scanners that Nimbis orchestrates.

This will download and install:
  • Trivy        - IaC, Secrets, Vulnerabilities
  • TruffleHog   - Secret detection
  • Grype        - Dependency vulnerabilities
  • Syft         - Software Bill of Materials

Manual installation required for:
  • Checkov      - pip3 install checkov
  • OpenGrep     - npm install -g @opengrep/cli`,
		Run: func(cmd *cobra.Command, args []string) {
			runSetup()
		},
	}

	var statusCmd = &cobra.Command{
		Use:   "status",
		Short: "Check which scanners are installed and available",
		Long:  `Display the status of all security scanners and their availability.`,
		Run: func(cmd *cobra.Command, args []string) {
			checkScannerStatus()
		},
	}

	// Scan command flags
	scanCmd.Flags().StringP("output", "o", "", "Output file for results")
	scanCmd.Flags().StringP("format", "f", "table", "Output format: table, json, sarif, html")
	scanCmd.Flags().StringP("scanners", "s", "", "Comma-separated list of scanners to use")
	scanCmd.Flags().StringP("severity", "", "LOW", "Minimum severity level: LOW, MEDIUM, HIGH, CRITICAL")
	scanCmd.Flags().StringP("fail-on", "", "CRITICAL", "Fail if issues at or above this severity are found")
	scanCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")
	scanCmd.Flags().BoolP("container", "", false, "Scan for container/Docker images")
	scanCmd.Flags().StringP("ai-provider", "", "", "AI provider for explanations: openai, anthropic, ollama")
	scanCmd.Flags().StringP("ai-model", "", "", "AI model to use")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(statusCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func showWelcomeScreen() {
	fmt.Println(`
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║                      Welcome to Nimbis v` + version + `                       ║
║                  Multi-Scanner Security Analysis Tool                   ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝

🔍 What is Nimbis?

   Nimbis orchestrates multiple open-source security scanners to provide
   comprehensive security analysis for your code, infrastructure, and 
   dependencies. Think of it as your security command center.

🛡️  What Nimbis Scans For:

   • Infrastructure as Code (IaC) misconfigurations
   • Hardcoded secrets and API keys
   • Dependency vulnerabilities (CVEs)
   • Static code analysis (SAST)
   • Software Bill of Materials (SBOM)

🔧 Supported Scanners:

   • Trivy        - IaC, Secrets, Vulnerabilities
   • TruffleHog   - Secret detection
   • Grype        - Dependency vulnerabilities  
   • Syft         - SBOM generation
   • Checkov      - IaC scanning (Python required)
   • OpenGrep     - SAST analysis (Node.js required)

📋 Quick Start Guide:

   1. Check scanner status:
      $ nimbis status

   2. Install scanners automatically:
      $ nimbis setup

   3. Run your first scan:
      $ nimbis scan .

   4. Scan with specific scanners:
      $ nimbis scan --scanners trivy-vuln,grype .

   5. Get detailed help:
      $ nimbis scan --help

💡 Pro Tips:

   • Use '--severity CRITICAL' to focus on critical issues only
   • Output results with '-o report.json -f json' for CI/CD integration
   • Enable AI explanations with '--ai-provider anthropic'

`)

	fmt.Print("Would you like to check scanner status now? [Y/n]: ")
	
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))
	
	if response == "" || response == "y" || response == "yes" {
		fmt.Println()
		checkScannerStatus()
		
		// Ask if they want to run setup
		fmt.Print("\nWould you like to install missing scanners? [Y/n]: ")
		response, _ = reader.ReadString('\n')
		response = strings.ToLower(strings.TrimSpace(response))
		
		if response == "" || response == "y" || response == "yes" {
			fmt.Println()
			runSetup()
		}
	} else {
		fmt.Println("\n💡 Run 'nimbis status' anytime to check scanner availability")
		fmt.Println("💡 Run 'nimbis setup' to install scanners")
		fmt.Println("💡 Run 'nimbis scan --help' for scanning options\n")
	}
}

func checkScannerStatus() {
	fmt.Println("┌─ SCANNER STATUS ─────────────────────────────────────────────────────┐")
	
	config := &ScanConfig{TargetPath: "."}
	available, unavailable := checkScannerAvailability(config)
	
	if len(available) > 0 {
		fmt.Println("\n✓ Available Scanners:")
		for _, scanner := range available {
			scanType := getScannerType(scanner.Name())
			fmt.Printf("  ✓ %-30s [%s]\n", scanner.Name(), scanType)
		}
	}
	
	if len(unavailable) > 0 {
		fmt.Println("\n✗ Missing Scanners:")
		for _, name := range unavailable {
			scanType := getScannerTypeByName(name)
			fmt.Printf("  ✗ %-30s [%s]\n", name, scanType)
		}
	}
	
	fmt.Println("└───────────────────────────────────────────────────────────────────────┘")
	
	if len(available) == 0 {
		fmt.Println("\n⚠️  No scanners are currently installed.")
		fmt.Println("💡 Run 'nimbis setup' to automatically install scanners")
	} else {
		fmt.Printf("\n✅ Ready to scan with %d scanner(s)\n", len(available))
	}
}

func runSetup() {
	fmt.Println("┌─ SCANNER SETUP ──────────────────────────────────────────────────────┐")
	fmt.Println("│                                                                       │")
	fmt.Println("│  Installing security scanners...                                     │")
	fmt.Println("│  This may take a few minutes on first run.                           │")
	fmt.Println("│                                                                       │")
	fmt.Println("└───────────────────────────────────────────────────────────────────────┘")
	fmt.Println()
	
	installer := NewScannerInstaller()
	
	scanners := []struct {
		name string
		fn   func() error
	}{
		{"Trivy", installer.installTrivy},
		{"TruffleHog", installer.installTruffleHog},
		{"Grype", installer.installGrype},
		{"Syft", installer.installSyft},
	}
	
	installed := 0
	failed := 0
	
	for _, s := range scanners {
		fmt.Printf("   Installing %-15s ", s.name+"...")
		if err := s.fn(); err != nil {
			fmt.Printf("⚠️  failed: %v\n", err)
			failed++
		} else {
			fmt.Println("✓")
			installed++
		}
	}
	
	fmt.Println()
	
	if installed > 0 {
		fmt.Printf("✅ Successfully installed %d/%d scanners\n\n", installed, len(scanners))
	} else {
		fmt.Println("❌ Installation failed for all scanners\n")
	}
	
	// Show manual installation instructions
	fmt.Println("💡 Additional scanners (manual installation):")
	fmt.Println("   • Checkov:  pip3 install checkov")
	fmt.Println("   • OpenGrep: npm install -g @opengrep/cli")
	fmt.Println()
	
	// Re-check status
	fmt.Println("Verifying installation...")
	fmt.Println()
	checkScannerStatus()
}

func runScan(cmd *cobra.Command, args []string) {
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	output, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	scanners, _ := cmd.Flags().GetString("scanners")
	severity, _ := cmd.Flags().GetString("severity")
	failOn, _ := cmd.Flags().GetString("fail-on")
	verbose, _ := cmd.Flags().GetBool("verbose")
	container, _ := cmd.Flags().GetBool("container")
	aiProvider, _ := cmd.Flags().GetString("ai-provider")
	aiModel, _ := cmd.Flags().GetString("ai-model")

	config := &ScanConfig{
		TargetPath:      targetPath,
		OutputFile:      output,
		OutputFormat:    format,
		SelectedScanners: scanners,
		MinSeverity:     severity,
		FailOnSeverity:  failOn,
		Verbose:         verbose,
		ScanContainer:   container,
		AIProvider:      aiProvider,
		AIModel:         aiModel,
	}

	// Show scan banner
	fmt.Println(`
    ███    ██ ██ ███    ███ ██████  ██ ███████ 
    ████   ██ ██ ████  ████ ██   ██ ██ ██      
    ██ ██  ██ ██ ██ ████ ██ ██████  ██ ███████ 
    ██  ██ ██ ██ ██  ██  ██ ██   ██ ██      ██ 
    ██   ████ ██ ██      ██ ██████  ██ ███████ 
                    v` + version + `
        IaC • Secrets • SAST • SCA • SBOM`)
	
	if err := runSecurityScan(config); err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		os.Exit(1)
	}
}

func getScannerType(name string) string {
	switch {
	case strings.Contains(name, "Trivy IaC"):
		return "IaC"
	case strings.Contains(name, "Trivy Secret"):
		return "Secrets"
	case strings.Contains(name, "Trivy Vulnerability"):
		return "SCA"
	case strings.Contains(name, "TruffleHog"):
		return "Secrets"
	case strings.Contains(name, "Checkov"):
		return "IaC"
	case strings.Contains(name, "OpenGrep"):
		return "SAST"
	case strings.Contains(name, "Grype"):
		return "SCA"
	case strings.Contains(name, "Syft"):
		return "SBOM"
	default:
		return "Security"
	}
}

func getScannerTypeByName(name string) string {
	return getScannerType(name)
}
