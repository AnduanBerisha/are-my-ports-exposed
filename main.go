package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

const banner = `
   ___   __  ___ ___  ____
  / _ | /  |/  / _ \/ __/
 / __ |/ /|_/ / ___/ _/  
/_/ |_/_/  /_/_/  /___/   v0.0.1
`

type Service struct {
	Port        int    `json:"port"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type Result struct {
	Service Service `json:"service"`
	IsOpen  bool    `json:"is_open"`
}

// Common sensitive ports often left exposed by mistake
var defaultAuditList = []Service{
	{Port: 21, Name: "FTP", Severity: "HIGH", Description: "Unencrypted file transfer protocol"},
	{Port: 22, Name: "SSH", Severity: "INFO", Description: "Remote administration service"},
	{Port: 2375, Name: "Docker Daemon", Severity: "CRITICAL", Description: "Unauthenticated Docker API endpoint"},
	{Port: 3306, Name: "MySQL", Severity: "CRITICAL", Description: "Relational database service"},
	{Port: 5432, Name: "PostgreSQL", Severity: "CRITICAL", Description: "Relational database service"},
	{Port: 6379, Name: "Redis", Severity: "CRITICAL", Description: "In-memory key-value data store"},
	{Port: 8080, Name: "HTTP-Alt", Severity: "INFO", Description: "Alternate web or admin dashboard port"},
	{Port: 9200, Name: "Elasticsearch", Severity: "CRITICAL", Description: "Search engine and analytics API"},
	{Port: 27017, Name: "MongoDB", Severity: "CRITICAL", Description: "Document-oriented database service"},
}

func checkPort(target string, svc Service, timeout time.Duration, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()

	addr := fmt.Sprintf("%s:%d", target, svc.Port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		results <- Result{Service: svc, IsOpen: false}
		return
	}
	conn.Close()
	results <- Result{Service: svc, IsOpen: true}
}

func main() {
	target := flag.String("host", "", "Target hostname or IP address to inspect")
	timeoutMs := flag.Int("timeout", 700, "Connection timeout in milliseconds")
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	flag.Parse()

	if *target == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -host <domain|ip> [-json] [-timeout ms]\n", os.Args[0])
		os.Exit(2)
	}

	if !*jsonOutput {
		fmt.Println(banner)
		fmt.Printf("[*] Auditing attack surface for: %s\n", *target)
		fmt.Printf("[*] Checking %d known high-risk ports...\n\n", len(defaultAuditList))
	}

	timeout := time.Duration(*timeoutMs) * time.Millisecond
	resultsChan := make(chan Result, len(defaultAuditList))
	var wg sync.WaitGroup

	for _, svc := range defaultAuditList {
		wg.Add(1)
		go checkPort(*target, svc, timeout, resultsChan, &wg)
	}

	wg.Wait()
	close(resultsChan)

	var exposed []Result
	for r := range resultsChan {
		if r.IsOpen {
			exposed = append(exposed, r)
		}
	}

	sort.Slice(exposed, func(i, j int) bool {
		return exposed[i].Service.Port < exposed[j].Service.Port
	})

	// Machine-readable output for pipelines
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(exposed); err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to encode output: %v\n", err)
			os.Exit(2)
		}
		if len(exposed) > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if len(exposed) == 0 {
		fmt.Println("[OK] No monitored ports are publicly accessible.")
		os.Exit(0)
	}

	hasCritical := false
	for _, res := range exposed {
		prefix := "[WARN]"
		switch res.Service.Severity {
		case "CRITICAL":
			prefix = "[CRITICAL]"
			hasCritical = true
		case "HIGH":
			prefix = "[HIGH]"
		case "INFO":
			prefix = "[INFO]"
		}

		fmt.Printf("%s Port %d/tcp (%s) is OPEN\n", prefix, res.Service.Port, res.Service.Name)
		fmt.Printf("       Description: %s\n", res.Service.Description)
	}

	fmt.Println("\nAction required: Restrict inbound access via cloud security groups or local firewall rules.")

	if hasCritical {
		os.Exit(1)
	}
}