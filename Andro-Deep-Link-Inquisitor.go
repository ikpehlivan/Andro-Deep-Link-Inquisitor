package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Terminal Color Constants for professional output formatting
const (
	InfoColor    = "\033[1;34m%s\033[0m"
	NoticeColor  = "\033[1;36m%s\033[0m"
	WarningColor = "\033[1;33m%s\033[0m"
	ErrorColor   = "\033[1;31m%s\033[0m"
	DebugColor   = "\033[0;36m%s\033[0m"
	SuccessColor = "\033[1;32m%s\033[0m"
)

// Data Structures for Manifest Parsing
type IntentFilter struct {
	Schemes []string
	Hosts   []string
	Paths   []string
}

type Activity struct {
	Name          string
	IsExported    bool
	IntentFilters []IntentFilter
}

type Inquisitor struct {
	ManifestPath string
	Activities   []Activity
}

// printBanner displays the ASCII art and tool information
func printBanner() {
	banner := `
    ___                __             ____                       __    _      __ 
   /   |  ____  ____  / /__________  / __ \___  ___  ____       / /   (_)____/ /_
  / /| | / __ \/ __ \/ ___/ ___/ __ \/ / / / _ \/ _ \/ __ \     / /   / / ___/ __/
 / ___ |/ / / / /_/ / /__/ /  / /_/ / /_/ /  __/  __/ /_/ /    / /___/ (__  ) /_  
/_/  |_/_/ /_/\__,_/\___/_/   \____/_____/\___/\___/ .___/____/_____/_/____/\__/  
      Mobile Deep Link Reconnaissance Tool        /_/   /_____/ v1.1.0
	`
	fmt.Printf(NoticeColor, banner)
	fmt.Println("\n---------------------------------------------------------------------------")
}

// Run executes the core analysis logic by parsing the XML file line by line
func (iq *Inquisitor) Run() {
	file, err := os.Open(iq.ManifestPath)
	if err != nil {
		fmt.Printf(ErrorColor, fmt.Sprintf("[-] Error: Could not open file: %v\n", err))
		return
	}
	defer file.Close()

	fmt.Printf(InfoColor, fmt.Sprintf("[*] Analysis Started: %s\n", iq.ManifestPath))

	var currentActivity *Activity
	var currentFilter *IntentFilter
	
	scanner := bufio.NewScanner(file)

	// Regex definitions for identifying Android components
	reActivity := regexp.MustCompile(`<activity.*android:name="([^"]+)"`)
	reExported := regexp.MustCompile(`android:exported="([^"]+)"`)
	reScheme   := regexp.MustCompile(`android:scheme="([^"]+)"`)
	reHost     := regexp.MustCompile(`android:host="([^"]+)"`)
	rePath     := regexp.MustCompile(`android:path="([^"]+)"`)

	for scanner.Scan() {
		line := scanner.Text()

		// Detect Activity start and extract attributes
		if strings.Contains(line, "<activity") {
			if currentActivity != nil {
				iq.Activities = append(iq.Activities, *currentActivity)
			}
			match := reActivity.FindStringSubmatch(line)
			name := "Unknown"
			if len(match) > 1 {
				name = match[1]
			}
			
			exported := false
			expMatch := reExported.FindStringSubmatch(line)
			if len(expMatch) > 1 && expMatch[1] == "true" {
				exported = true
			}

			currentActivity = &Activity{Name: name, IsExported: exported}
		}

		// Detect Intent-filter blocks
		if strings.Contains(line, "<intent-filter") {
			currentFilter = &IntentFilter{}
		}

		// Extract Data elements (Scheme, Host, Path)
		if strings.Contains(line, "<data") {
			if currentFilter != nil {
				if s := reScheme.FindStringSubmatch(line); len(s) > 1 {
					currentFilter.Schemes = append(currentFilter.Schemes, s[1])
				}
				if h := reHost.FindStringSubmatch(line); len(h) > 1 {
					currentFilter.Hosts = append(currentFilter.Hosts, h[1])
				}
				if p := rePath.FindStringSubmatch(line); len(p) > 1 {
					currentFilter.Paths = append(currentFilter.Paths, p[1])
				}
			}
		}

		// Handle Intent-filter closing tag
		if strings.Contains(line, "</intent-filter>") {
			if currentActivity != nil && currentFilter != nil {
				currentActivity.IntentFilters = append(currentActivity.IntentFilters, *currentFilter)
				currentFilter = nil
			}
		}

		// Handle Activity closing tag
		if strings.Contains(line, "</activity>") {
			if currentActivity != nil {
				iq.Activities = append(iq.Activities, *currentActivity)
				currentActivity = nil
			}
		}
	}
	
	iq.GenerateReport()
}

// GenerateReport prints the findings and produces ADB Proof-of-Concept commands
func (iq *Inquisitor) GenerateReport() {
	vulnCount := 0
	fmt.Println("\n[+] Discovered Deep Link Structures & Analysis Results:")
	
	for _, act := range iq.Activities {
		if len(act.IntentFilters) == 0 {
			continue
		}

		status := "INTERNAL"
		if act.IsExported {
			status = "EXPORTED (HIGH RISK)"
		}

		fmt.Printf("\n--- Target Activity: %s ---\n", act.Name)
		if act.IsExported {
			fmt.Printf(WarningColor, fmt.Sprintf("  [!] Security Status: %s\n", status))
			vulnCount++
		} else {
			fmt.Printf("  [+] Security Status: %s\n", status)
		}

		for _, filter := range act.IntentFilters {
			for _, scheme := range filter.Schemes {
				// Process Host and Path combinations
				for _, host := range filter.Hosts {
					fullPath := ""
					if len(filter.Paths) > 0 {
						fullPath = filter.Paths[0]
					}
					
					uri := fmt.Sprintf("%s://%s%s", scheme, host, fullPath)
					fmt.Printf(NoticeColor, fmt.Sprintf("    > Identified URI: %s\n", uri))
					
					// Generate ADB POC Command
					adbCmd := fmt.Sprintf("adb shell am start -W -a android.intent.action.VIEW -d \"%s\"", uri)
					fmt.Printf(DebugColor, fmt.Sprintf("      POC Exploit: %s\n", adbCmd))
				}
				
				// Handle Scheme-only Deep Links (no host defined)
				if len(filter.Hosts) == 0 {
					uri := fmt.Sprintf("%s://", scheme)
					fmt.Printf(NoticeColor, fmt.Sprintf("    > Identified URI: %s (Scheme Only)\n", uri))
					adbCmd := fmt.Sprintf("adb shell am start -W -a android.intent.action.VIEW -d \"%s\"", uri)
					fmt.Printf(DebugColor, fmt.Sprintf("      POC Exploit: %s\n", adbCmd))
				}
			}
		}
	}

	fmt.Println("\n---------------------------------------------------------------------------")
	fmt.Printf(SuccessColor, fmt.Sprintf("[*] Scan Complete. Found %d potentially vulnerable Activities.\n", vulnCount))
}

func main() {
	printBanner()

	// Command line flag definition
	manifestPtr := flag.String("manifest", "", "Path to the decompiled AndroidManifest.xml file")
	flag.Parse()

	// Validation check for input file
	if *manifestPtr == "" {
		fmt.Printf(ErrorColor, "[-] Error: No manifest file specified.\n")
		fmt.Println("Usage: go run main.go -manifest AndroidManifest.xml")
		os.Exit(1)
	}

	// Initialize and start the Inquisitor
	inquisitor := &Inquisitor{
		ManifestPath: *manifestPtr,
	}

	inquisitor.Run()
}