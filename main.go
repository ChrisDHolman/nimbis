package main

import (
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
		Short: "Nimbis - Multi-Scanner Security Analysis",
		Long: `
    ███    ██ ██ ███    ███ ██████  ██ ███████ 
    ████   ██ ██ ████  ████ ██   ██ ██ ██      
    ██ ██  ██ ██ ██ ████ ██ ██████  ██ ███████ 
    ██  ██ ██ ██ ██  ██  ██ ██   ██ ██      ██ 
    ██   ████ ██ ██      ██ ██████  ██ ███████ 
                    v` + version + `

    Multi-Scanner Security Analysis Framework
    IaC • Secrets • SAST • SCA • SBOM
`,
		Run: func(cmd *cobra.Command, args []string) {
			showBanner()
			showQuickHelp()
		},
	}

	var scanCmd = &cobra.Command{
		Use:   "scan [path]",
		Short: "Execute security scan",
		Long:  `Execute comprehensive security scan using configured scanners.`,
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runScan(cmd, args)
		},
	}

	var statusCmd = &cobra.Command{
		Use:   "status",
		Short: "Display scanner status",
		Long:  `Display installation status of all security scanners.`,
		Run: func(cmd *cobra.Command, args []string) {
			showBanner()
			checkScannerStatus()
		},
	}

	var setupCmd = &cobra.Command{
		Use:   "setup",
		Short: "Install security scanners",
		Long:  `Download and install security scanning tools.`,
		Run: func(cmd *cobra.Command, args []string) {
			showBanner()
			runSetup()
		},
	}

	// Scan flags
	scanCmd.Flags().StringP("output", "o", "", "Output file path")
	scanCmd.Flags().StringP("format", "f", "table", "Output format (table|json|sarif|html)")
	scanCmd.Flags().StringP("severity", "s", "LOW", "Minimum severity (LOW|MEDIUM|HIGH|CRITICAL)")
	scanCmd.Flags().String("fail-on", "CRITICAL", "Exit with error on severity")
	scanCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
	scanCmd.Flags().BoolP("quiet", "q", false, "Minimal output")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(setupCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}
}

func showBanner() {
	fmt.Println()
	fmt.Printf("%s", BrightCyan)
	fmt.Println("    ███    ██ ██ ███    ███ ██████  ██ ███████ ")
	fmt.Println("    ████   ██ ██ ████  ████ ██   ██ ██ ██      ")
	fmt.Println("    ██ ██  ██ ██ ██ ████ ██ ██████  ██ ███████ ")
	fmt.Println("    ██  ██ ██ ██ ██  ██  ██ ██   ██ ██      ██ ")
	fmt.Println("    ██   ████ ██ ██      ██ ██████  ██ ███████ ")
	fmt.Printf("%s", Reset)
	fmt.Printf("                    %sv%s%s\n", Dim, version, Reset)
	fmt.Println()
}

func showQuickHelp() {
	fmt.Println("Multi-Scanner Security Analysis Framework")
	fmt.Println()
	fmt.Printf("%s=[ %sNimbis v%s%s                                            ]=%s\n", Dim, BrightWhite, version, Dim, Reset)
	fmt.Printf("%s+ -- --=[ %s8 security scanners%s                              ]%s\n", Dim, BrightGreen, Dim, Reset)
	fmt.Printf("%s+ -- --=[ %sIaC | Secrets | SAST | SCA | SBOM%s               ]%s\n", Dim, BrightCyan, Dim, Reset)
	fmt.Println()
	
	commands := []struct {
		name string
		desc string
	}{
		{"nimbis scan [path]", "Execute security scan"},
		{"nimbis status", "Show scanner status"},
		{"nimbis setup", "Install scanners"},
		{"nimbis scan --help", "Show scan options"},
	}
	
	fmt.Printf("%sCommands%s\n", Bold, Reset)
	fmt.Println(strings.Repeat("─", 50))
	for _, cmd := range commands {
		fmt.Printf("  %-25s %s%s%s\n", cmd.name, Dim, cmd.desc, Reset)
	}
	fmt.Println()
}

func checkScannerStatus() {
	scanners := []struct {
		name     string
		scanType string
		checker  func() bool
	}{
		{"Trivy", "IaC/Secrets/SCA", func() bool { return NewTrivyIaCScanner().IsAvailable() }},
		{"TruffleHog", "Secrets", func() bool { return NewTruffleHogScanner().IsAvailable() }},
		{"Checkov", "IaC", func() bool { return NewCheckovScanner().IsAvailable() }},
		{"OpenGrep", "SAST", func() bool { return NewOpenGrepScanner().IsAvailable() }},
		{"Grype", "SCA", func() bool { return NewGrypeScanner().IsAvailable() }},
		{"Syft", "SBOM", func() bool { return NewSyftScanner().IsAvailable() }},
	}
	
	available := 0
	missing := []string{}
	
	fmt.Printf("%sScanner Status%s\n", Bold, Reset)
	fmt.Println(strings.Repeat("─", 60))
	
	for _, s := range scanners {
		if s.checker() {
			fmt.Printf("  %s[+]%s %-20s %s%-20s%s %sOK%s\n", 
				BrightGreen, Reset, s.name, Dim, s.scanType, Reset, BrightGreen, Reset)
			available++
		} else {
			fmt.Printf("  %s[-]%s %-20s %s%-20s%s %sNot Found%s\n", 
				BrightRed, Reset, s.name, Dim, s.scanType, Reset, BrightRed, Reset)
			missing = append(missing, s.name)
		}
	}
	
	fmt.Println()
	fmt.Printf("%s[*]%s %d/%d scanners available\n", BrightCyan, Reset, available, len(scanners))
	
	if len(missing) > 0 {
		fmt.Printf("%s[!]%s Missing: %s\n", BrightYellow, Reset, strings.Join(missing, ", "))
		fmt.Printf("%s[*]%s Run '%snimbis setup%s' to install\n", BrightCyan, Reset, BrightWhite, Reset)
	}
	
	fmt.Println()
}

func runSetup() {
	// Check if already installed
	if NewTrivyIaCScanner().IsAvailable() && 
	   NewTruffleHogScanner().IsAvailable() && 
	   NewGrypeScanner().IsAvailable() && 
	   NewSyftScanner().IsAvailable() {
		fmt.Printf("%s[*]%s All scanners already installed\n", BrightGreen, Reset)
		fmt.Println()
		return
	}
	
	fmt.Printf("%s[*]%s Initializing scanner installation...\n", BrightCyan, Reset)
	fmt.Println()
	
	installer, err := NewScannerInstaller()
	if err != nil {
		fmt.Printf("%s[-]%s Failed to initialize: %v\n", BrightRed, Reset, err)
		return
	}
	
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
	
	for _, s := range scanners {
		fmt.Printf("%s[*]%s Installing %s... ", BrightCyan, Reset, s.name)
		if err := s.fn(); err != nil {
			fmt.Printf("%s✗ %v%s\n", BrightRed, err, Reset)
		} else {
			fmt.Printf("%s✓%s\n", BrightGreen, Reset)
			installed++
		}
	}
	
	fmt.Println()
	
	if installed == len(scanners) {
		fmt.Printf("%s[+]%s Installation complete (%d/%d)\n", BrightGreen, Reset, installed, len(scanners))
	} else if installed > 0 {
		fmt.Printf("%s[!]%s Partial installation (%d/%d)\n", BrightYellow, Reset, installed, len(scanners))
	} else {
		fmt.Printf("%s[-]%s Installation failed\n", BrightRed, Reset)
	}
	
	// Show manual installation note
	if !NewCheckovScanner().IsAvailable() || !NewOpenGrepScanner().IsAvailable() {
		fmt.Println()
		fmt.Printf("%s[*]%s Additional scanners (manual):\n", BrightCyan, Reset)
		if !NewCheckovScanner().IsAvailable() {
			fmt.Printf("    %s•%s Checkov: %spip3 install checkov%s\n", Dim, Reset, BrightWhite, Reset)
		}
		if !NewOpenGrepScanner().IsAvailable() {
			fmt.Printf("    %s•%s OpenGrep: %snpm install -g @opengrep/cli%s\n", Dim, Reset, BrightWhite, Reset)
		}
	}
	
	fmt.Println()
}

func runScan(cmd *cobra.Command, args []string) {
	targetPath := "."
	if len(args) > 0 {
		targetPath = args[0]
	}

	output, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	severity, _ := cmd.Flags().GetString("severity")
	failOn, _ := cmd.Flags().GetString("fail-on")
	verbose, _ := cmd.Flags().GetBool("verbose")
	quiet, _ := cmd.Flags().GetBool("quiet")

	scanTypes := ScanTypes{
		IaC:     true,
		Secrets: true,
		SAST:    true,
		SCA:     true,
		SBOM:    true,
	}

	config := &ScanConfig{
		TargetPath:     targetPath,
		OutputFile:     output,
		OutputFormat:   format,
		MinSeverity:    severity,
		FailOnSeverity: failOn,
		Verbose:        verbose,
		Quiet:          quiet,
		ScanTypes:      scanTypes,
	}

	if !quiet {
		showBanner()
	}
	
	scanner := NewScanner(config)
	if err := scanner.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n%s[-]%s %v\n", BrightRed, Reset, err)
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
