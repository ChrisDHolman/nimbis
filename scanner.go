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
		fmt.Printf("%s[*]%s Detecting scanners...\n", BrightCyan, Reset)
	}
	
	availableScanners := []string{}
	unavailableScanners := []string{}
	
	for name, scanner := range s.scanners {
		if scanner.IsAvailable() {
			availableScanners = append(availableScanners, name)
			if s.config.Verbose {
				fmt.Printf("  %s[+]%s %s\n", BrightGreen, Reset, scanner.Name())
			}
		} else {
			unavailableScanners = append(unavailableScanners, scanner.Name())
			if s.config.Verbose {
				fmt.Printf("  %s[-]%s %s\n", Dim, Reset, scanner.Name())
			}
			delete(s.scanners, name)
		}
	}
	
	s.results.Metadata.Scanners = availableScanners
	
	if !s.config.Quiet {
		fmt.Printf("%s[*]%s %d scanners ready\n", BrightGreen, Reset, len(availableScanners))
		fmt.Println()
	}
	
	if len(availableScanners) == 0 {
		fmt.Printf("%s[-]%s No scanners available\n", BrightRed, Reset)
		fmt.Printf("%s[*]%s Run '%snimbis setup%s' to install\n", BrightCyan, Reset, BrightWhite, Reset)
		os.Exit(1)
	}
}

// runParallel runs all scanners in parallel
func (s *Scanner) runParallel() {
	if !s.config.Quiet {
		fmt.Printf("%s[*]%s Executing scans...\n", BrightCyan, Reset)
		fmt.Println()
	}
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	type scanResult struct {
		scanner       ScannerInterface
		findings      []Finding
		filteredCount int
		err           error
	}
	
	results := make(chan scanResult, len(s.scanners))
	
	for name, scanner := range s.scanners {
		wg.Add(1)
		go func(n string, sc ScannerInterface) {
			defer wg.Done()
			
			findings, err := sc.Scan(s.config)
			
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
			if s.config.Verbose {
				fmt.Printf("  %s[-]%s %s: %v\n", BrightRed, Reset, result.scanner.Name(), result.err)
			}
			continue
		}
		
		mu.Lock()
		s.appendFindings(result.findings)
		mu.Unlock()
		
		if s.config.Verbose && result.filteredCount > 0 {
			fmt.Printf("  %s[+]%s %s (%d findings)\n", BrightGreen, Reset, result.scanner.Name(), result.filteredCount)
		}
	}
	
	if !s.config.Quiet {
		fmt.Println()
	}
}

// runSequential runs all scanners sequentially
func (s *Scanner) runSequential() {
	if !s.config.Quiet {
		fmt.Printf("%s[*]%s Executing scans...\n", BrightCyan, Reset)
		fmt.Println()
	}
	
	minLevel := s.getSeverityLevel(s.config.MinSeverity)
	
	for _, scanner := range s.scanners {
		if s.config.Verbose {
			fmt.Printf("  %s[*]%s %s... ", BrightCyan, Reset, scanner.Name())
		}
		
		findings, err := scanner.Scan(s.config)
		if err != nil {
			if s.config.Verbose {
				fmt.Printf("%s✗%s\n", BrightRed, Reset)
			}
			if s.config.Verbose {
				fmt.Printf("      %s%v%s\n", Dim, err, Reset)
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
		
		if s.config.Verbose {
			if len(filteredFindings) > 0 {
				fmt.Printf("%s✓%s %s(%d findings)%s\n", BrightGreen, Reset, Dim, len(filteredFindings), Reset)
			} else {
				fmt.Printf("%s✓%s\n", BrightGreen, Reset)
			}
		}
	}
	
	if !s.config.Quiet {
		fmt.Println()
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
			fmt.Printf("%s[*]%s Results saved: %s%s%s\n", BrightCyan, Reset, BrightWhite, s.config.OutputFile, Reset)
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
	allFindings := append(s.results.IaCResults, s.results.SecretResults...)
	allFindings = append(allFindings, s.results.SASTResults...)
	allFindings = append(allFindings, s.results.SCAResults...)
	
	if len(allFindings) == 0 {
		return
	}
	
	fmt.Printf("%sTop Findings%s\n", Bold, Reset)
	fmt.Println(strings.Repeat("─", 60))
	
	minSeverityLevel := s.getSeverityLevel(s.config.MinSeverity)
	
	severityGroups := map[string][]Finding{
		SeverityCritical: {},
		SeverityHigh:     {},
		SeverityMedium:   {},
		SeverityLow:      {},
	}
	
	for _, f := range allFindings {
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
		
		if s.getSeverityLevel(targetSeverity) >= minSeverityLevel {
			severityGroups[targetSeverity] = append(severityGroups[targetSeverity], f)
		}
	}
	
	shown := 0
	maxShow := 10
	
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if s.getSeverityLevel(sev) < minSeverityLevel {
			continue
		}
		
		findings := severityGroups[sev]
		if len(findings) == 0 {
			continue
		}
		
		var color string
		switch sev {
		case SeverityCritical:
			color = BrightRed
		case SeverityHigh:
			color = Red
		case SeverityMedium:
			color = Yellow
		case SeverityLow:
			color = Green
		}
		
		for _, f := range findings {
			if shown >= maxShow {
				remaining := len(allFindings) - shown
				if remaining > 0 {
					fmt.Printf("\n  %s[*]%s ... and %d more findings\n", Dim, Reset, remaining)
				}
				goto done
			}
			
			location := ""
			if f.File != "" {
				location = truncateMiddle(f.File, 30)
				if f.Line > 0 {
					location += fmt.Sprintf(":%d", f.Line)
				}
			}
			
			fmt.Printf("\n  %s[%s]%s %s\n", color, sev, Reset, truncateScanner(f.Title, 50))
			if location != "" {
				fmt.Printf("      %s└─%s %s%s%s\n", Dim, Reset, Dim, location, Reset)
			}
			
			shown++
		}
	}
	
done:
	fmt.Println()
	
	if s.config.OutputFile != "" {
		fmt.Printf("%s[*]%s Full report: %s%s%s\n", BrightCyan, Reset, BrightWhite, s.config.OutputFile, Reset)
	} else {
		fmt.Printf("%s[*]%s Save full report: %snimbis scan -o results.json%s\n", 
			BrightCyan, Reset, Dim, Reset)
	}
	
	fmt.Println()
}

// printSummary prints a human-readable summary
func (s *Scanner) printSummary() {
	fmt.Printf("%sResults%s\n", Bold, Reset)
	fmt.Println(strings.Repeat("─", 60))
	
	fmt.Printf("  %s[*]%s Total findings:   %s%d%s\n", 
		BrightCyan, Reset, BrightWhite, s.results.Summary.TotalFindings, Reset)
	fmt.Printf("  %s[*]%s Scan duration:    %s%s%s\n", 
		BrightCyan, Reset, BrightWhite, s.results.Summary.ScanDuration, Reset)
	fmt.Printf("  %s[*]%s Scanners used:    %s%d%s\n", 
		BrightCyan, Reset, BrightWhite, len(s.results.Metadata.Scanners), Reset)
	
	if len(s.results.Summary.FindingsBySeverity) > 0 {
		fmt.Println()
		fmt.Printf("%sSeverity Distribution%s\n", Bold, Reset)
		fmt.Println(strings.Repeat("─", 60))
		
		for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
			if count, ok := s.results.Summary.FindingsBySeverity[sev]; ok && count > 0 {
				var color string
				switch sev {
				case SeverityCritical:
					color = BrightRed
				case SeverityHigh:
					color = Red
				case SeverityMedium:
					color = Yellow
				case SeverityLow:
					color = Green
				}
				fmt.Printf("  %s%-10s%s %s%d%s\n", color, sev, Reset, BrightWhite, count, Reset)
			}
		}
	}
	
	if len(s.results.Summary.FindingsByType) > 0 {
		fmt.Println()
		fmt.Printf("%sFinding Types%s\n", Bold, Reset)
		fmt.Println(strings.Repeat("─", 60))
		for scanType, count := range s.results.Summary.FindingsByType {
			fmt.Printf("  %s%-10s%s %s%d%s\n", Cyan, scanType, Reset, BrightWhite, count, Reset)
		}
	}
	
	fmt.Println()
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
			return fmt.Errorf("found %d issue(s) at or above %s severity", count, s.config.FailOnSeverity)
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
