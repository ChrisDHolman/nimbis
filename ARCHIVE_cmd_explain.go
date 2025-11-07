package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// This replaces the existing command_explain.go file completely

var explainCmd = &cobra.Command{
	Use:   "explain",
	Short: "Explain security findings using AI",
	Long: `Use AI to explain security findings in plain language with actionable fix suggestions.
Supports OpenAI, Anthropic Claude, and local Ollama models.

The explain command always runs a fresh security scan, then explains the findings.
Use the global --severity flag to control which findings are scanned and explained.

Examples:
  # Scan and explain all findings (default: top 10)
  nimbis explain

  # Scan for HIGH+ findings and explain all of them
  nimbis --severity HIGH explain

  # Scan for MEDIUM+ and explain top 50
  nimbis --severity MEDIUM explain --max 50

  # Scan for CRITICAL only and explain all
  nimbis --severity CRITICAL explain --max 100

  # Filter explained findings further (scan all, explain only CRITICAL)
  nimbis explain --min-severity CRITICAL`,
	RunE: runExplainAI,
}

var (
	explainMaxFindings int
	explainSeverity    string
	explainProvider    string
	explainInteractive bool
)

func init() {
	explainCmd.Flags().IntVar(&explainMaxFindings, "max", 10, "Maximum number of findings to explain")
	explainCmd.Flags().StringVar(&explainSeverity, "min-severity", "", "Minimum severity to explain (LOW, MEDIUM, HIGH, CRITICAL). If not set, explains all findings from scan")
	explainCmd.Flags().StringVar(&explainProvider, "provider", "", "Force specific AI provider (anthropic, openai, ollama)")
	explainCmd.Flags().BoolVar(&explainInteractive, "interactive", false, "Interactive mode - ask questions about findings")
}

func runExplainAI(cmd *cobra.Command, args []string) error {
	fmt.Println("🤖 Nimbis AI Explanation")
	fmt.Println()

	// Always run a fresh scan to ensure consistency
	resultsFile := "nimbis-results.json"
	fmt.Println("🔍 Running security scan...")
	
	// Use the global severity flag if set, otherwise scan everything
	scanSeverity := severity
	if scanSeverity == "" {
		scanSeverity = "LOW"
	}
	
	// Create a scanner with all scan types enabled
	config := &ScanConfig{
		TargetPath:     targetPath,
		OutputFormat:   "json",
		OutputFile:     resultsFile,
		MinSeverity:    scanSeverity, // Respect global --severity flag
		FailOnSeverity: "CRITICAL",
		Parallel:       true,
		Verbose:        false,
		AutoInstall:    autoInstall,
		Quiet:          true,
		ScanTypes: ScanTypes{
			IaC:     true,
			Secrets: true,
			SAST:    true,
			SCA:     true,
		},
	}
	
	scanner := NewScanner(config)
	if err := scanner.Run(); err != nil {
		// Ignore exit errors from findings, we still want to explain them
		if !strings.Contains(err.Error(), "scan failed: found") {
			return fmt.Errorf("scan failed: %w", err)
		}
	}
	fmt.Println()

	// Load scan results
	results, err := loadScanResults(resultsFile)
	if err != nil {
		return fmt.Errorf("failed to load scan results: %w", err)
	}

	// Combine all findings from different result arrays
	allFindings := make([]Finding, 0)
	allFindings = append(allFindings, results.IaCResults...)
	allFindings = append(allFindings, results.SecretResults...)
	allFindings = append(allFindings, results.SASTResults...)
	allFindings = append(allFindings, results.SCAResults...)

	if len(allFindings) == 0 {
		fmt.Println("✅ No security findings to explain. Your code looks good!")
		return nil
	}

	// Configure AI provider
	fmt.Println("🔧 Configuring AI provider...")
	aiConfig, err := GetAIConfig()
	if err != nil {
		return fmt.Errorf("AI configuration failed: %w\n\nTo use AI explanations, set one of:\n  • ANTHROPIC_API_KEY=your-key\n  • OPENAI_API_KEY=your-key\n  • Run Ollama locally (http://localhost:11434)", err)
	}

	providerName := string(aiConfig.Provider)
	if aiConfig.Provider == ProviderAnthropic {
		providerName = "Anthropic Claude"
	} else if aiConfig.Provider == ProviderOpenAI {
		providerName = "OpenAI GPT"
	} else if aiConfig.Provider == ProviderOllama {
		providerName = "Ollama (local)"
	}
	
	fmt.Printf("  ✓ Using %s (%s)\n", providerName, aiConfig.Model)
	fmt.Println()

	// Filter findings by severity only if --min-severity is explicitly set
	var filteredFindings []Finding
	if explainSeverity != "" {
		filteredFindings = filterFindingsBySeverity(allFindings, explainSeverity)
		
		if len(filteredFindings) == 0 {
			fmt.Printf("No findings at or above %s severity\n", explainSeverity)
			return nil
		}
	} else {
		// No filter - explain all findings from scan
		filteredFindings = allFindings
	}

	// Limit findings to explain
	if len(filteredFindings) > explainMaxFindings {
		if explainSeverity != "" {
			fmt.Printf("📊 Explaining top %d of %d findings at %s+ severity (use --max to adjust)\n\n", 
				explainMaxFindings, len(filteredFindings), explainSeverity)
		} else {
			fmt.Printf("📊 Explaining top %d of %d findings (use --max to adjust)\n\n", 
				explainMaxFindings, len(filteredFindings))
		}
		filteredFindings = filteredFindings[:explainMaxFindings]
	} else {
		if explainSeverity != "" {
			fmt.Printf("📊 Explaining %d findings at %s+ severity\n\n", len(filteredFindings), explainSeverity)
		} else {
			fmt.Printf("📊 Explaining all %d findings\n\n", len(filteredFindings))
		}
	}

	// Create explanation request
	request := ExplanationRequest{
		Findings: filteredFindings,
		Severity: explainSeverity,
		MaxCount: explainMaxFindings,
	}

	// Get AI explanation
	fmt.Println("💭 Analyzing findings with AI...")
	explanation, err := ExplainFindings(aiConfig, request)
	if err != nil {
		return fmt.Errorf("explanation failed: %w", err)
	}

	// Display explanation
	fmt.Print(FormatExplanation(explanation))

	// Show individual findings with context
	fmt.Println("📋 DETAILED FINDINGS")
	fmt.Println("─────────────────────────────────────────────────────────")
	
	for i, finding := range filteredFindings {
		if i >= explainMaxFindings {
			break
		}
		fmt.Printf("\n%d. ", i+1)
		displayFindingDetail(finding)
	}

	// Save explanation to file
	explainFile := strings.TrimSuffix(resultsFile, filepath.Ext(resultsFile)) + "-explanation.txt"
	if err := saveExplanation(explainFile, explanation, filteredFindings); err != nil {
		fmt.Printf("\n⚠ Warning: Could not save explanation to file: %v\n", err)
	} else {
		fmt.Printf("\n💾 Full explanation saved to: %s\n", explainFile)
	}

	// Interactive mode
	if explainInteractive {
		fmt.Println("\n" + strings.Repeat("─", 70))
		fmt.Println("💬 Interactive Mode - Ask questions about these findings")
		fmt.Println("   (Type 'exit' to quit)")
		fmt.Println(strings.Repeat("─", 70))
		
		// Simple interactive loop could be added here
		fmt.Println("\nℹ Interactive mode coming soon!")
	}

	return nil
}

func loadScanResults(filename string) (*ScanResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var results ScanResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}

	return &results, nil
}

func filterFindingsBySeverity(findings []Finding, minSeverity string) []Finding {
	severityOrder := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}

	minLevel := severityOrder[strings.ToUpper(minSeverity)]
	filtered := make([]Finding, 0)

	for _, finding := range findings {
		if severityOrder[finding.Severity] >= minLevel {
			filtered = append(filtered, finding)
		}
	}

	// Sort by severity (highest first)
	for i := 0; i < len(filtered)-1; i++ {
		for j := 0; j < len(filtered)-i-1; j++ {
			if severityOrder[filtered[j].Severity] < severityOrder[filtered[j+1].Severity] {
				filtered[j], filtered[j+1] = filtered[j+1], filtered[j]
			}
		}
	}

	return filtered
}

func displayFindingDetail(finding Finding) {
	// Severity icon and color
	var icon string
	switch finding.Severity {
	case "CRITICAL":
		icon = "🔴"
	case "HIGH":
		icon = "🟠"
	case "MEDIUM":
		icon = "🟡"
	case "LOW":
		icon = "🟢"
	default:
		icon = "⚪"
	}

	fmt.Printf("%s %s - %s\n", icon, finding.Severity, finding.Title)
	
	if finding.CVE != "" {
		fmt.Printf("   CVE: %s\n", finding.CVE)
	}
	
	// Get package info from Extra map
	if finding.Extra != nil {
		if pkg, ok := finding.Extra["package"]; ok && pkg != "" {
			packageInfo := pkg
			if version, ok := finding.Extra["installed_version"]; ok && version != "" {
				packageInfo += fmt.Sprintf(" (v%s)", version)
			}
			fmt.Printf("   📦 Package: %s\n", packageInfo)
		}
	}
	
	if finding.File != "" {
		location := finding.File
		if finding.Line > 0 {
			location += fmt.Sprintf(":%d", finding.Line)
		}
		fmt.Printf("   📍 Location: %s\n", location)
	}
	
	if finding.Description != "" && len(finding.Description) < 150 {
		fmt.Printf("   💬 %s\n", finding.Description)
	}
	
	if finding.Remediation != "" {
		fmt.Printf("   💡 Fix: %s\n", finding.Remediation)
	}
	
	if finding.References != nil && len(finding.References) > 0 && len(finding.References[0]) > 0 {
		fmt.Printf("   🔗 %s\n", finding.References[0])
	}
}

func saveExplanation(filename string, explanation *ExplanationResponse, findings []Finding) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write header
	f.WriteString("═══════════════════════════════════════════════════════════\n")
	f.WriteString("  NIMBIS AI SECURITY EXPLANATION\n")
	f.WriteString("═══════════════════════════════════════════════════════════\n\n")

	// Write summary
	f.WriteString("SUMMARY\n")
	f.WriteString("───────────────────────────────────────────────────────────\n")
	f.WriteString(explanation.Summary)
	f.WriteString("\n\n")

	// Write recommendations
	if len(explanation.Recommendations) > 0 {
		f.WriteString("KEY RECOMMENDATIONS\n")
		f.WriteString("───────────────────────────────────────────────────────────\n")
		for i, rec := range explanation.Recommendations {
			f.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
		f.WriteString("\n")
	}

	// Write findings
	f.WriteString("DETAILED FINDINGS\n")
	f.WriteString("───────────────────────────────────────────────────────────\n\n")
	
	for i, finding := range findings {
		f.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, finding.Severity, finding.Title))
		
		if finding.CVE != "" {
			f.WriteString(fmt.Sprintf("   CVE: %s\n", finding.CVE))
		}
		// Get package from Extra map
		if finding.Extra != nil {
			if pkg, ok := finding.Extra["package"]; ok && pkg != "" {
				f.WriteString(fmt.Sprintf("   Package: %s", pkg))
				if version, ok := finding.Extra["installed_version"]; ok && version != "" {
					f.WriteString(fmt.Sprintf(" (v%s)", version))
				}
				f.WriteString("\n")
			}
		}
		if finding.File != "" {
			location := finding.File
			if finding.Line > 0 {
				location += fmt.Sprintf(":%d", finding.Line)
			}
			f.WriteString(fmt.Sprintf("   Location: %s\n", location))
		}
		if finding.Description != "" {
			f.WriteString(fmt.Sprintf("   Description: %s\n", finding.Description))
		}
		if finding.Remediation != "" {
			f.WriteString(fmt.Sprintf("   Remediation: %s\n", finding.Remediation))
		}
		f.WriteString("\n")
	}

	return nil
}
