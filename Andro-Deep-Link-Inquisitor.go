package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Terminal Color Constants
const (
	InfoColor    = "\033[1;34m%s\033[0m"
	NoticeColor  = "\033[1;36m%s\033[0m"
	WarningColor = "\033[1;33m%s\033[0m"
	ErrorColor   = "\033[1;31m%s\033[0m"
	DebugColor   = "\033[0;36m%s\033[0m"
	SuccessColor = "\033[1;32m%s\033[0m"
)

var redirectParams = []string{"url", "redirect", "target", "link", "view", "goto", "path", "callback"}

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
	ManifestPath     string
	CollaboratorURLs []string
	Activities       []Activity
}

func printBanner() {
	banner := `
    ___                __             ____                       __    _      __ 
   /   |  ____  ____  / /__________  / __ \___  ___  ____       / /   (_)____/ /_
  / /| | / __ \/ __ \/ ___/ ___/ __ \/ / / / _ \/ _ \/ __ \     / /   / / ___/ __/
 / ___ |/ / / / /_/ / /__/ /  / /_/ / /_/ /  __/  __/ /_/ /    / /___/ (__  ) /_  
/_/  |_/_/ /_/\__,_/\___/_/   \____/_____/\___/\___/ .___/____/_____/_/____/\__/  
      Mobile Deep Link Reconnaissance Tool        /_/   /_____/ v1.3.0
	`
	fmt.Printf(NoticeColor, banner)
	fmt.Println("\n---------------------------------------------------------------------------")
}

// readCollaboratorFile reads payloads from an external .txt file
func readCollaboratorFile(filename string) []string {
	var urls []string
	file, err := os.Open(filename)
	if err != nil {
		return urls // Return empty if file doesn't exist
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	return urls
}

func (iq *Inquisitor) Run() {
	file, err := os.Open(iq.ManifestPath)
	if err != nil {
		fmt.Printf(ErrorColor, fmt.Sprintf("[-] Error: Could not open manifest: %v\n", err))
		return
	}
	defer file.Close()

	fmt.Printf(InfoColor, fmt.Sprintf("[*] Analysis Started: %s\n", iq.ManifestPath))
	if len(iq.CollaboratorURLs) > 0 {
		fmt.Printf(SuccessColor, fmt.Sprintf("[+] Loaded %d Collaborator URLs from file.\n", len(iq.CollaboratorURLs)))
	}

	var currentActivity *Activity
	var currentFilter *IntentFilter
	scanner := bufio.NewScanner(file)

	reActivity := regexp.MustCompile(`<activity.*android:name="([^"]+)"`)
	reExported := regexp.MustCompile(`android:exported="([^"]+)"`)
	reScheme   := regexp.MustCompile(`android:scheme="([^"]+)"`)
	reHost     := regexp.MustCompile(`android:host="([^"]+)"`)
	rePath     := regexp.MustCompile(`android:path="([^"]+)"`)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "<activity") {
			if currentActivity != nil {
				iq.Activities = append(iq.Activities, *currentActivity)
			}
			match := reActivity.FindStringSubmatch(line)
			name := "Unknown"; if len(match) > 1 { name = match[1] }
			exported := false
			expMatch := reExported.FindStringSubmatch(line)
			if len(expMatch) > 1 && expMatch[1] == "true" { exported = true }
			currentActivity = &Activity{Name: name, IsExported: exported}
		}

		if strings.Contains(line, "<intent-filter") { currentFilter = &IntentFilter{} }

		if strings.Contains(line, "<data") && currentFilter != nil {
			if s := reScheme.FindStringSubmatch(line); len(s) > 1 { currentFilter.Schemes = append(currentFilter.Schemes, s[1]) }
			if h := reHost.FindStringSubmatch(line); len(h) > 1 { currentFilter.Hosts = append(currentFilter.Hosts, h[1]) }
			if p := rePath.FindStringSubmatch(line); len(p) > 1 { currentFilter.Paths = append(currentFilter.Paths, p[1]) }
		}

		if strings.Contains(line, "</intent-filter>") && currentActivity != nil && currentFilter != nil {
			currentActivity.IntentFilters = append(currentActivity.IntentFilters, *currentFilter)
			currentFilter = nil
		}

		if strings.Contains(line, "</activity>") && currentActivity != nil {
			iq.Activities = append(iq.Activities, *currentActivity)
			currentActivity = nil
		}
	}
	iq.GenerateReport()
}

func (iq *Inquisitor) GenerateReport() {
	vulnCount := 0
	fmt.Println("\n[+] Discovered Deep Link Structures & Analysis Results:")
	
	for _, act := range iq.Activities {
		if len(act.IntentFilters) == 0 { continue }

		status := "INTERNAL"; if act.IsExported { status = "EXPORTED (HIGH RISK)" }

		fmt.Printf("\n--- Target Activity: %s ---\n", act.Name)
		if act.IsExported {
			fmt.Printf(WarningColor, fmt.Sprintf("  [!] Security Status: %s\n", status))
			vulnCount++
		}

		for _, filter := range act.IntentFilters {
			for _, scheme := range filter.Schemes {
				for _, host := range filter.Hosts {
					fullPath := ""
					if len(filter.Paths) > 0 { fullPath = filter.Paths[0] }
					baseURI := fmt.Sprintf("%s://%s%s", scheme, host, fullPath)
					iq.printPocs(baseURI, act.IsExported)
				}
				if len(filter.Hosts) == 0 {
					uri := fmt.Sprintf("%s://", scheme)
					iq.printPocs(uri, act.IsExported)
				}
			}
		}
	}
	fmt.Println("\n---------------------------------------------------------------------------")
	fmt.Printf(SuccessColor, fmt.Sprintf("[*] Scan Complete. Found %d potentially vulnerable Activities.\n", vulnCount))
}

func (iq *Inquisitor) printPocs(uri string, isExported bool) {
	fmt.Printf(NoticeColor, fmt.Sprintf("    > Identified URI: %s\n", uri))
	fmt.Printf(DebugColor, fmt.Sprintf("      Standard POC: adb shell am start -W -a android.intent.action.VIEW -d \"%s\"\n", uri))

	if isExported && len(iq.CollaboratorURLs) > 0 {
		fmt.Printf(WarningColor, "      [?] Redirection Payloads (Multi-URL Mode):\n")
		for _, collab := range iq.CollaboratorURLs {
			for _, param := range redirectParams {
				separator := "?"
				if strings.Contains(uri, "?") { separator = "&" }
				fullPayload := fmt.Sprintf("%s%s%s=%s", uri, separator, param, collab)
				fmt.Printf(ErrorColor, fmt.Sprintf("        Test [%s]: adb shell am start -W -a android.intent.action.VIEW -d \"%s\"\n", collab, fullPayload))
			}
		}
	}
}

func main() {
	printBanner()
	manifestPtr := flag.String("manifest", "", "Path to AndroidManifest.xml")
	collabFilePtr := flag.String("file", "Collaborator-URLs.txt", "File containing Collaborator URLs")
	flag.Parse()

	if *manifestPtr == "" {
		fmt.Printf(ErrorColor, "[-] Error: No manifest specified.\n")
		os.Exit(1)
	}

	inquisitor := &Inquisitor{
		ManifestPath:     *manifestPtr,
		CollaboratorURLs: readCollaboratorFile(*collabFilePtr),
	}
	inquisitor.Run()
}
