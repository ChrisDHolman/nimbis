package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Scanner orchestrates multiple security scanners
type Scanner struct {
	config   *ScanConfig
	scanners map[string]ScannerInterface
	results  *ScanResult
}

// NewScanner creates a new scanner orchestrator
func NewScanner(config *ScanConfig) *Scanner {
	s := &Scanner{
		config: config,
		results: &ScanResult{
			Summary: Summary{
				FindingsBySeverity: make(map[string]int),
				FindingsByType:     make(map[string]int),
			},
			Metadata: Metadata{
				ToolName:    "Nimbis",
				ToolVersion: version,
				TargetPath:  config.TargetPath,
				StartTime:   time.Now(),
			},
		},
	}

	// Initialize scanners based on config
	s.scanners = make(map[string]ScannerInterface)
	
	if config.ScanTypes.IaC {
		s.scanners["trivy-iac"] = NewTrivyIaCScanner()
		s.scanners["checkov"] = NewCheckovScanner()
	}
	
	if config.ScanTypes.Secrets {
		s.scanners["trufflehog"] = NewTruffleHogScanner()
		s.scanners["trivy-secret"] = NewTrivySecretScanner()
	}
	
	if config.ScanTypes.SAST {
		s.scanners["opengrep"] = NewOpenGrepScanner()
	}
	
	if config.ScanTypes.SCA {
		s.scanners["trivy-vuln"] = NewTrivyVulnScanner()
		s.scanners["grype"] = NewGrypeScanner()
	}
	
	if config.ScanTypes.SBOM {
		s.scanners["syft"] = NewSyftScanner()
	}

	return s
}

// Run executes all configured scanners
func (s *Scanner) Run() error {
	// Print banner (skip if quiet mode)
	if !s.config.Quiet {
		PrintBanner()
	} else {
		PrintCompactBanner()
	}
	
	PrintScanStart(s.config.TargetPath)

	// Check scanner availability
	s.checkScannerAvailability()

	// Run scanners
	if s.config.Parallel {
		s.runParallel()
	} else {
		s.runSequential()
	}

	s.results.Metadata.EndTime = time.Now()
	s.results.Summary.ScanDuration = s.results.Metadata.EndTime.Sub(s.results.Metadata.StartTime).String()

	// Calculate summary
	s.calculateSummary()

	// Output results
	return s.outputResults()
}

// checkScannerAvailability checks which scanners are available
func (s *Scanner) checkScannerAvailability() {
	if !s.config.Quiet {
		PrintSectionHeader("SCANNER DETECTION")
	}
	
	availableScanners := []string{}
	
	for name, scanner := range s.scanners {
		if scanner.IsAvailable() {
			availableScanners = append(availableScanners, name)
			if s.config.Verbose && !s.config.Quiet {
				PrintScanProgress(scanner.Name(), "completed", 0)
			}
		} else {
			if !s.config.Quiet {
				PrintScanProgress(scanner.Name(), "skipped", 0)
			}
			delete(s.scanners, name)
		}
	}
	
	s.results.Metadata.Scanners = availableScanners
	
	if !s.config.Quiet {
		PrintSectionFooter()
		fmt.Printf("\n%s%d%s scanners ready\n", BrightGreen, len(availableScanners), Reset)
	}
	
	if len(availableScanners) == 0 {
		// Offer to auto-install
		PrintError("No scanners available")
		
		shouldInstall := s.config.AutoInstall
		if !shouldInstall {
			fmt.Println("\nWould you like to auto-install scanners? (y/n)")
			fmt.Print("> ")
			
			var response string
			fmt.Scanln(&response)
			shouldInstall = strings.ToLower(strings.TrimSpace(response)) == "y"
		}
		
		if shouldInstall {
			installer, err := NewScannerInstaller()
			if err != nil {
				fmt.Printf("Failed to create installer: %v\n", err)
				os.Exit(1)
			}
			
			if err := installer.InstallAll(); err != nil {
				fmt.Printf("Installation failed: %v\n", err)
				os.Exit(1)
			}
			
			installer.AddToPath()
			
			// Re-check availability after installation
			fmt.Println("🔧 Re-checking scanner availability...")
			s.scanners = make(map[string]ScannerInterface)
			
			if s.config.ScanTypes.IaC {
				s.scanners["trivy-iac"] = NewTrivyIaCScanner()
				s.scanners["checkov"] = NewCheckovScanner()
			}
			
			if s.config.ScanTypes.Secrets {
				s.scanners["trufflehog"] = NewTruffleHogScanner()
				s.scanners["trivy-secret"] = NewTrivySecretScanner()
			}
			
			if s.config.ScanTypes.SAST {
				s.scanners["opengrep"] = NewOpenGrepScanner()
			}
			
			if s.config.ScanTypes.SCA {
				s.scanners["trivy-vuln"] = NewTrivyVulnScanner()
				s.scanners["grype"] = NewGrypeScanner()
			}
			
			if s.config.ScanTypes.SBOM {
				s.scanners["syft"] = NewSyftScanner()
			}
			
			availableScanners = []string{}
			for name, scanner := range s.scanners {
				if scanner.IsAvailable() {
					availableScanners = append(availableScanners, name)
					fmt.Printf("  ✓ %s\n", scanner.Name())
				} else {
					delete(s.scanners, name)
				}
			}
			
			if len(availableScanners) == 0 {
				fmt.Println("\n❌ Installation completed but scanners still not available.")
				fmt.Println("\n💡 Manual installation instructions:")
				fmt.Println("  • Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
				fmt.Println("  • TruffleHog: https://github.com/trufflesecurity/trufflehog")
				fmt.Println("  • Checkov: pip3 install checkov")
				fmt.Println("  • Grype: https://github.com/anchore/grype")
				fmt.Println("  • Syft: https://github.com/anchore/syft")
				fmt.Println("  • OpenGrep: npm install -g @opengrep/cli")
				os.Exit(1)
			}
			
			s.results.Metadata.Scanners = availableScanners
			fmt.Printf("\n✅ Ready to scan with %d scanner(s)\n\n", len(availableScanners))
			return
		}
		
		fmt.Println("\nManual installation instructions:")
		fmt.Println("  • Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
		fmt.Println("  • TruffleHog: https://github.com/trufflesecurity/trufflehog")
		fmt.Println("  • Checkov: pip3 install checkov")
		fmt.Println("  • Grype: https://github.com/anchore/grype")
		fmt.Println("  • Syft: https://github.com/anchore/syft")
		fmt.Println("  • OpenGrep: npm install -g @opengrep/cli")
		os.Exit(1)
	}
}

// runParallel runs all scanners in parallel
func (s *Scanner) runParallel() {
	if !s.config.Quiet {
		PrintSectionHeader("SCANNING")
	}
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	type scanResult struct {
		scanner     ScannerInterface
		findings    []Finding
		totalCount  int
		filteredCount int
		err         error
	}
	
	results := make(chan scanResult, len(s.scanners))
	
	for name, scanner := range s.scanners {
		wg.Add(1)
		go func(n string, sc ScannerInterface) {
			defer wg.Done()
			
			if !s.config.Quiet {
				PrintScanProgress(sc.Name(), "running", 0)
			}
			
			findings, err := sc.Scan(s.config)
			
			totalCount := len(findings)
			filteredCount := 0
			
			// Filter findings by severity
			if err == nil {
				minLevel := s.getSeverityLevel(s.config.MinSeverity)
				filteredFindings := []Finding{}
				for _, f := range findings {
					if s.getSeverityLevel(f.Severity) >= minLevel {
						filteredFindings = append(filteredFindings, f)
						filteredCount++
					}
				}
				findings = filteredFindings
			}
			
			results <- scanResult{
				scanner:       sc,
				findings:      findings,
				totalCount:    totalCount,
				filteredCount: filteredCount,
				err:           err,
			}
		}(name, scanner)
	}
	
	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect results
	for result := range results {
		if result.err != nil {
			if !s.config.Quiet {
				PrintScanProgress(result.scanner.Name(), "failed", 0)
				if s.config.Verbose {
					PrintWarning(fmt.Sprintf("%s: %v", result.scanner.Name(), result.err))
				}
			}
			continue
		}
		
		mu.Lock()
		s.appendFindings(result.findings)
		mu.Unlock()
		
		if !s.config.Quiet {
			PrintScanProgress(result.scanner.Name(), "completed", result.filteredCount)
		}
	}
	
	if !s.config.Quiet {
		PrintSectionFooter()
	}
}

// runSequential runs all scanners sequentially
func (s *Scanner) runSequential() {
	if !s.config.Quiet {
		PrintSectionHeader("SCANNING")
	}
	
	minLevel := s.getSeverityLevel(s.config.MinSeverity)
	
	for _, scanner := range s.scanners {
		if !s.config.Quiet {
			PrintScanProgress(scanner.Name(), "running", 0)
		}
		
		findings, err := scanner.Scan(s.config)
		if err != nil {
			if !s.config.Quiet {
				PrintScanProgress(scanner.Name(), "failed", 0)
				if s.config.Verbose {
					PrintWarning(fmt.Sprintf("%s: %v", scanner.Name(), err))
				}
			}
			continue
		}
		
		// Filter by severity
		filteredFindings := []Finding{}
		for _, f := range findings {
			if s.getSeverityLevel(f.Severity) >= minLevel {
				filteredFindings = append(filteredFindings, f)
			}
		}
		
		s.appendFindings(filteredFindings)
		
		if !s.config.Quiet {
			PrintScanProgress(scanner.Name(), "completed", len(filteredFindings))
		}
	}
	
	if !s.config.Quiet {
		PrintSectionFooter()
	}
}

// appendFindings adds findings to the appropriate result category
func (s *Scanner) appendFindings(findings []Finding) {
	for _, f := range findings {
		switch f.Type {
		case ScanTypeIaC:
			s.results.IaCResults = append(s.results.IaCResults, f)
		case ScanTypeSecret:
			s.results.SecretResults = append(s.results.SecretResults, f)
		case ScanTypeSAST:
			s.results.SASTResults = append(s.results.SASTResults, f)
		case ScanTypeSCA:
			s.results.SCAResults = append(s.results.SCAResults, f)
		}
	}
}

// calculateSummary calculates summary statistics
func (s *Scanner) calculateSummary() {
	// Use the already filtered findings from the result arrays
	allFindings := append(s.results.IaCResults, s.results.SecretResults...)
	allFindings = append(allFindings, s.results.SASTResults...)
	allFindings = append(allFindings, s.results.SCAResults...)
	
	s.results.Summary.TotalFindings = len(allFindings)
	
	// Count by severity and type
	for _, f := range allFindings {
		// Normalize severity for counting
		normalizedSeverity := strings.ToUpper(f.Severity)
		switch normalizedSeverity {
		case "CRITICAL":
			s.results.Summary.FindingsBySeverity[SeverityCritical]++
		case "HIGH":
			s.results.Summary.FindingsBySeverity[SeverityHigh]++
		case "MEDIUM":
			s.results.Summary.FindingsBySeverity[SeverityMedium]++
		case "LOW":
			s.results.Summary.FindingsBySeverity[SeverityLow]++
		default:
			s.results.Summary.FindingsBySeverity[SeverityLow]++
		}
		
		s.results.Summary.FindingsByType[f.Type]++
	}
}

// getSeverityLevel returns numeric level for severity comparison
func (s *Scanner) getSeverityLevel(severity string) int {
	switch strings.ToUpper(severity) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// outputResults outputs the scan results
func (s *Scanner) outputResults() error {
	// Always save full results to file if in quiet mode
	if s.config.Quiet && s.config.OutputFile == "" {
		s.config.OutputFile = "nimbis-results.json"
		s.config.OutputFormat = "json"
	}
	
	// Generate formatted output for file
	if s.config.OutputFile != "" {
		formatter := NewFormatter(s.config.OutputFormat, s.results)
		output, err := formatter.Format()
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}
		
		if err := os.WriteFile(s.config.OutputFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		
		if !s.config.Quiet {
			fmt.Printf("\n📄 Full results saved to: %s\n", s.config.OutputFile)
		}
	}
	
	// Print summary (always shown unless quiet mode with no findings)
	if !s.config.Quiet || s.results.Summary.TotalFindings > 0 {
		s.printSummary()
		
		// Print brief findings overview
		if s.results.Summary.TotalFindings > 0 {
			s.printBriefFindings()
		}
	}
	
	// Check if we should fail based on severity
	return s.checkFailCondition()
}

// printBriefFindings prints a brief overview of findings
func (s *Scanner) printBriefFindings() {
	// Use the already filtered results from calculateSummary
	allFindings := append(s.results.IaCResults, s.results.SecretResults...)
	allFindings = append(allFindings, s.results.SASTResults...)
	allFindings = append(allFindings, s.results.SCAResults...)
	
	if len(allFindings) == 0 {
		return
	}
	
	PrintSectionHeader("FINDINGS OVERVIEW")
	
	// Get minimum severity level
	minSeverityLevel := s.getSeverityLevel(s.config.MinSeverity)
	
	// Group by severity (only those that meet the threshold)
	severityGroups := map[string][]Finding{
		SeverityCritical: {},
		SeverityHigh:     {},
		SeverityMedium:   {},
		SeverityLow:      {},
	}
	
	for _, f := range allFindings {
		// Normalize severity
		normalizedSeverity := strings.ToUpper(f.Severity)
		var targetSeverity string
		
		switch normalizedSeverity {
		case "CRITICAL":
			targetSeverity = SeverityCritical
		case "HIGH":
			targetSeverity = SeverityHigh
		case "MEDIUM":
			targetSeverity = SeverityMedium
		case "LOW":
			targetSeverity = SeverityLow
		default:
			targetSeverity = SeverityLow
		}
		
		// Only include if it meets minimum severity
		if s.getSeverityLevel(targetSeverity) >= minSeverityLevel {
			severityGroups[targetSeverity] = append(severityGroups[targetSeverity], f)
		}
	}
	
	// Print each severity group (only those at or above threshold)
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		// Skip if below minimum severity
		if s.getSeverityLevel(sev) < minSeverityLevel {
			continue
		}
		
		findings := severityGroups[sev]
		if len(findings) == 0 {
			continue
		}
		
		fmt.Printf("\n%s%s (%d issues)%s\n", Bold, ColorSeverity(sev), len(findings), Reset)
		
		for i, f := range findings {
			// Limit to 5 per severity level for readability
			if i >= 5 {
				fmt.Printf("\n   %s... and %d more %s issues%s\n", Dim, len(findings)-5, sev, Reset)
				break
			}
			
			// Format finding based on type
			location := ""
			if f.File != "" {
				location = truncateMiddle(f.File, 35)
				if f.Line > 0 {
					location += fmt.Sprintf(":%d", f.Line)
				}
			}
			
			PrintFinding(sev, truncateScanner(f.Title, 55), location, truncateScanner(f.Remediation, 55))
		}
	}
	
	PrintSectionFooter()
	
	if s.config.OutputFile != "" {
		PrintInfo(fmt.Sprintf("Full details saved to: %s", s.config.OutputFile))
	} else {
		PrintInfo("Run with -o results.json to save full details")
	}
}

// printSummary prints a human-readable summary
func (s *Scanner) printSummary() {
	stats := map[string]interface{}{
		"Total Findings":   s.results.Summary.TotalFindings,
		"Scan Duration":    s.results.Summary.ScanDuration,
		"Scanners Used":    len(s.results.Metadata.Scanners),
	}
	
	PrintSummaryBox("SCAN SUMMARY", stats)
	
	if len(s.results.Summary.FindingsBySeverity) > 0 {
		fmt.Printf("\n%sSeverity Breakdown:%s\n", Bold, Reset)
		for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
			if count, ok := s.results.Summary.FindingsBySeverity[sev]; ok && count > 0 {
				fmt.Printf("  %s %d\n", ColorSeverity(sev), count)
			}
		}
	}
	
	if len(s.results.Summary.FindingsByType) > 0 {
		fmt.Printf("\n%sFindings by Type:%s\n", Bold, Reset)
		for scanType, count := range s.results.Summary.FindingsByType {
			fmt.Printf("  %s• %s:%s %d\n", Cyan, scanType, Reset, count)
		}
	}
}

// checkFailCondition checks if the scan should fail based on severity threshold
func (s *Scanner) checkFailCondition() error {
	severityOrder := map[string]int{
		SeverityLow:      1,
		SeverityMedium:   2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}
	
	failThreshold := severityOrder[s.config.FailOnSeverity]
	
	for sev, count := range s.results.Summary.FindingsBySeverity {
		if count > 0 && severityOrder[sev] >= failThreshold {
			return fmt.Errorf("scan failed: found %d issue(s) at or above %s severity", count, s.config.FailOnSeverity)
		}
	}
	
	return nil
}

func truncateScanner(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func truncateMiddle(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	
	// Keep start and end, replace middle with ...
	keepLen := (maxLen - 3) / 2
	return s[:keepLen] + "..." + s[len(s)-keepLen:]
}
