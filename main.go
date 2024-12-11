package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// FilterProfile represents a structured profile of filtered traffic
type FilterProfile struct {
	DashboardType string
	Filters       map[string][]string
}

var filterNameMap = map[string]string{
	"src-ip":             "Source IP",
	"src-asn":            "Source ASN",
	"protocol":           "Protocol",
	"tcp-flag":           "TCP Flags",
	"dest-ip":            "Destination IP",
	"dest-port":          "Destination Port",
	"src-port":           "Source Port",
	"http-method":        "Method",
	"ja4":                "JA4",
	"coloCode":           "Colo Location",
	"ja3-hash":           "JA3",
	"client-ip":          "Client IP",
	"status-code":        "Response Code",
	"asn":                "ASN",
	"rule-id":            "WAF Rule ID",
	"path":               "Path",
	"user-agent":         "User Agent",
	"host":               "Hostname",
	"country":            "Country",
	"referer":            "Referer",
	"origin-status-code": "Origin response code",
	"mitigation-system":  "Mitigation system",
}

func main() {
	// Get the URL input from command-line arguments or prompt the user
	inputURL := getInputURL()

	// Parse the URL
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		fmt.Println("Invalid URL:", err)
		return
	}

	// Extract query parameters
	queryParams := parsedURL.Query()

	// Determine the dashboard type
	dashboardType := getDashboardType(parsedURL.Path)

	// Build the filter profile
	profile := buildFilterProfile(queryParams, dashboardType)

	// Display the fingerprint/profile in Markdown format
	displayProfileAsMarkdown(profile)
}

// getInputURL retrieves the URL from the command-line arguments or prompts the user
func getInputURL() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}

	// Prompt the user for a URL if not provided in the command-line arguments
	fmt.Print("Enter the Cloudflare dashboard URL: ")
	reader := bufio.NewReader(os.Stdin)
	url, _ := reader.ReadString('\n')
	return strings.TrimSpace(url)
}

// getDashboardType determines the dashboard type based on the URL path
func getRequiredFilters(dashboardType string) []string {
	if dashboardType == "L3 - Network Analytics" {
		return []string{"dest-ip", "src-ip", "protocol", "src-asn", "dest-port", "src-port", "tcp-flag", "src-asn"}
	} else if dashboardType == "L7 - Security or Analytics" {

	}
	return []string{}
}

func getDashboardType(path string) string {
	if strings.Contains(path, "network-analytics") {
		return "L3 - Network Analytics"
	} else if strings.Contains(path, "analytics") || strings.Contains(path, "security") {
		return "L7 - Security or Analytics"
	}
	return "Unknown"
}

// buildFilterProfile creates a FilterProfile from query parameters
func buildFilterProfile(params url.Values, dashboardType string) FilterProfile {
	profile := FilterProfile{
		DashboardType: dashboardType,
		Filters:       make(map[string][]string),
	}

	// Extract known filters and add them to the profile
	for key, values := range params {
		normalizedKey := strings.TrimSuffix(key, "~in") // Remove ~in if present
		if len(values) > 0 {
			profile.Filters[normalizedKey] = strings.Split(values[0], ",")
		}
	}

	return profile
}

// displayProfileAsMarkdown prints the FilterProfile in Markdown-compatible format
func displayProfileAsMarkdown(profile FilterProfile) {
	fmt.Printf("# Dashboard Type: %s\n\n", profile.DashboardType)

	if len(profile.Filters) == 0 {
		fmt.Println("No filters applied.")
		return
	}

	//TODO: Have needed filters, that if missing per dash will display "Distributed"

	fmt.Println("## Profile:")
	for key, values := range profile.Filters {
		filterName := key

		value, exists := filterNameMap[key]
		if exists {
			filterName = value
		}
		if key == "date-to" || key == "date-from" {
			continue
		}

		if len(values) > 1 {
			// Print as a Markdown list if it's a list of values

			//TODO: Have a custom Keyname lookup for Labels to look pretty for customers.

			fmt.Printf("- **%s**:\n", filterName)
			for _, value := range values {
				fmt.Printf("  - %s\n", value)
			}
		} else {
			// Print as a single line if it's a single value
			fmt.Printf("- **%s**: %s\n", filterName, values[0])
		}
	}
}
