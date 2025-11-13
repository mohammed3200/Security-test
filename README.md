# 🔒 SQL Injection Vulnerability Tester

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/yourusername/sqli-tester)
[![Go Version](https://img.shields.io/badge/Go-1.19+-00ADD8.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A comprehensive, concurrent SQL injection vulnerability scanner written in Go. This tool tests web applications for SQL injection vulnerabilities using multiple attack vectors including boolean-based, time-based, UNION-based, error-based, and NoSQL injection techniques.

## ⚡ Features

- **Multiple Attack Vectors**: 70+ SQL injection payloads covering:
  - Boolean-based blind SQLi
  - Time-based blind SQLi (MySQL, PostgreSQL, SQL Server, Oracle)
  - UNION-based SQLi
  - Error-based SQLi
  - Stacked queries
  - NoSQL injection patterns
  - Encoding bypass techniques

- **Advanced Detection**:
  - SQL error signature detection across multiple DBMS (MySQL, PostgreSQL, SQL Server, Oracle, SQLite)
  - Response length analysis
  - Time-based blind SQLi detection
  - HTTP status code change detection
  - Severity classification (HIGH, MEDIUM, LOW)
  - Confidence scoring

- **Performance**:
  - Concurrent testing with configurable workers
  - Baseline comparison for accurate detection
  - Request retry mechanism
  - Configurable delays between requests

- **Comprehensive Reporting**:
  - **JSON** - Machine-readable detailed findings
  - **HTML** - Beautiful, interactive visual report
  - **CSV** - Spreadsheet-compatible data export
  - Vulnerability severity classification
  - Per-URL and per-field statistics

- **Flexibility**:
  - Single or multi-URL testing
  - GET and POST methods
  - Custom headers support
  - Proxy support (e.g., for Burp Suite)
  - SSL certificate verification control
  - Custom User-Agent strings

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Examples](#examples)
- [Report Interpretation](#report-interpretation)
- [Remediation Guide](#remediation-guide)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [License](#license)

## 🚀 Installation

### Prerequisites

- Go 1.19 or higher

### Build from Source

```bash
# Clone the repository
git clone https://github.com/mohammed3200/sqli-tester.git
cd sqli-tester

# Build the binary
go build -o sqli-tester main.go

# Or install directly
go install
```

### Binary Download

Download pre-compiled binaries from the [Releases](https://github.com/yourusername/sqli-tester/releases) page.

## 🎯 Quick Start

### Basic Single URL Test

```bash
./sqli-tester \
  -url https://example.com/login \
  -method POST \
  -fields username,password
```

### Multiple URLs Test

```bash
./sqli-tester \
  -urls https://site1.com/login,https://site2.com/search \
  -method POST \
  -fields user,pass
```

### URLs from File

```bash
./sqli-tester \
  -urls-file targets.txt \
  -fields username,password \
  -concurrency 10
```

## 📖 Usage

### Command-Line Options

```
Required Flags:
  -url string
        Target URL (single). Example: https://example.com/login
  -urls string
        Comma-separated URLs to test
  -urls-file string
        Path to file with one URL per line
  -fields string
        Comma-separated field names to test. Example: username,password
  -method string
        HTTP method: POST or GET (default "POST")

Optional Flags:
  -timeout int
        HTTP client timeout seconds (default 15)
  -concurrency int
        Number of concurrent workers (default 6)
  -out string
        Path to JSON report file (default "sqli_report.json")
  -html string
        Path to HTML report file (default "sqli_report.html")
  -csv string
        Path to CSV report file (optional)
  -proxy string
        Proxy URL (e.g., http://127.0.0.1:8080)
  -headers string
        Custom headers (format: Key1:Value1,Key2:Value2)
  -user-agent string
        Custom User-Agent string (default "SQLi-Tester/3.0")
  -follow-redirects
        Follow HTTP redirects (default true)
  -verify-ssl
        Verify SSL certificates (default true)
  -verbose
        Verbose output (show all findings)
  -delay int
        Delay between requests in milliseconds (default 0)
  -retries int
        Maximum retries for failed requests (default 2)
  -version
        Show version and exit
```

## 💡 Examples

### Example 1: Basic Login Form Test

```bash
./sqli-tester \
  -url https://vulnerable-site.com/login.php \
  -method POST \
  -fields username,password \
  -out results.json \
  -html report.html
```

### Example 2: GET Parameter Testing

```bash
./sqli-tester \
  -url https://shop.example.com/products \
  -method GET \
  -fields id,category \
  -concurrency 10
```

### Example 3: Testing with Proxy (Burp Suite)

```bash
./sqli-tester \
  -url https://example.com/api/user \
  -method POST \
  -fields user_id \
  -proxy http://127.0.0.1:8080 \
  -verify-ssl=false
```

### Example 4: Custom Headers and Authentication

```bash
./sqli-tester \
  -url https://api.example.com/search \
  -method POST \
  -fields query \
  -headers "Authorization:Bearer YOUR_TOKEN,X-API-Key:12345" \
  -user-agent "Mozilla/5.0 Custom Scanner"
```

### Example 5: Multiple URLs from File

Create `targets.txt`:
```
https://site1.com/login.php
https://site2.com/admin/index.php
https://site3.com/search
```

Run the test:
```bash
./sqli-tester \
  -urls-file targets.txt \
  -method POST \
  -fields username,password,email \
  -concurrency 15 \
  -csv export.csv \
  -verbose
```

### Example 6: Rate-Limited Testing

```bash
./sqli-tester \
  -url https://example.com/login \
  -fields username,password \
  -delay 500 \
  -concurrency 3 \
  -retries 3
```

## 📊 Report Interpretation

### Severity Levels

The tool classifies findings into three severity levels:

#### 🔴 HIGH Severity
- **SQL error signatures detected** - Direct evidence of SQL injection
- **Time-based delays confirmed** - Significant response delays matching payload expectations
- **Action Required**: Immediate remediation needed

#### 🟡 MEDIUM Severity
- **Significant response length changes** - Indicates potential data manipulation
- **HTTP status code changes** - Suggests different query behaviors
- **Action Required**: Investigation and testing recommended

#### 🔵 LOW Severity
- **Minor response variations** - May indicate filtering or errors
- **Potential false positives** - Requires manual verification
- **Action Required**: Manual review suggested

### Confidence Scores

- **High**: Strong indicators of vulnerability (e.g., SQL error messages)
- **Medium-High**: Time-based delays with consistent patterns
- **Medium**: Response length deviations
- **Low**: Minor anomalies requiring verification

### Payload Types

- **Union-based**: UNION SELECT attacks for data extraction
- **Time-based**: SLEEP/WAITFOR attacks for blind SQLi
- **Boolean-based**: True/false logic manipulation
- **Error-based**: Provokes database errors for information disclosure
- **NoSQL**: MongoDB and other NoSQL injection patterns
- **Generic**: General SQL injection attempts

### Reading the HTML Report

The HTML report provides:

1. **Summary Dashboard**:
   - Total tests executed
   - Vulnerabilities found by severity
   - Test duration and configuration

2. **Per-URL Analysis**:
   - Vulnerability count per endpoint
   - Field-by-field breakdown
   - Detailed findings table

3. **Detailed Findings Table**:
   - Each tested payload with its result
   - Color-coded by severity
   - Response metrics (status, size, duration)

## 🛡️ Remediation Guide

### Immediate Actions for Detected Vulnerabilities

#### 1. Use Prepared Statements (Parameterized Queries)

**PHP (PDO)**:
```php
// ❌ VULNERABLE
$query = "SELECT * FROM users WHERE username = '$_POST[username]'";

// ✅ SECURE
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$_POST['username']]);
```

**PHP (MySQLi)**:
```php
// ✅ SECURE
$stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $_POST['username'], $_POST['password']);
$stmt->execute();
```

**Python**:
```python
# ❌ VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# ✅ SECURE
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

**Node.js (MySQL2)**:
```javascript
// ✅ SECURE
connection.execute(
  'SELECT * FROM users WHERE username = ? AND password = ?',
  [username, password]
);
```

#### 2. Input Validation and Sanitization

```php
// Validate input types
$user_id = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
if ($user_id === false) {
    die("Invalid user ID");
}

// Whitelist validation for known values
$allowed_sort = ['name', 'date', 'price'];
$sort = in_array($_GET['sort'], $allowed_sort) ? $_GET['sort'] : 'name';
```

#### 3. Principle of Least Privilege

```sql
-- Create restricted database user
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE ON webapp_db.* TO 'webapp'@'localhost';
-- Don't grant DELETE, DROP, or admin privileges
```

#### 4. Error Handling

```php
// ❌ DON'T expose database errors
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

// ✅ Log errors securely
try {
    // Database operations
} catch (Exception $e) {
    error_log($e->getMessage()); // Log to file
    die("An error occurred"); // Generic message to user
}
```

#### 5. Web Application Firewall (WAF)

Deploy the provided `.htaccess` rules or use cloud-based WAF solutions:
- Cloudflare
- AWS WAF
- ModSecurity

#### 6. Regular Security Audits

```bash
# Schedule regular testing
0 2 * * 0 /usr/local/bin/sqli-tester -urls-file /etc/targets.txt -out /var/log/security/sqli_$(date +\%Y\%m\%d).json
```

### Long-term Security Improvements

1. **Code Review**: Implement secure code review processes
2. **Security Training**: Train developers on secure coding practices
3. **Dependency Management**: Keep all libraries and frameworks updated
4. **Penetration Testing**: Schedule regular professional security audits
5. **Bug Bounty Program**: Consider a responsible disclosure program

## ⚖️ Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing only.

### Legal Usage

✅ **Permitted**:
- Testing your own applications
- Testing with explicit written permission
- Educational purposes in controlled environments
- Bug bounty programs with proper authorization

❌ **Prohibited**:
- Testing systems without authorization
- Unauthorized penetration testing
- Malicious activities
- Attacking production systems without consent

### Your Responsibilities

- **Obtain written authorization** before testing any system
- **Respect scope limitations** defined by the target owner
- **Report vulnerabilities responsibly** to affected parties
- **Comply with all applicable laws** in your jurisdiction

**Unauthorized access to computer systems is illegal in most jurisdictions (e.g., CFAA in the US, Computer Misuse Act in the UK). The authors assume no liability for misuse of this tool.**

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Reporting Issues

- Use GitHub Issues
- Provide clear reproduction steps
- Include version information
- Share anonymized reports if possible

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines

- Follow Go best practices
- Add tests for new features
- Update documentation
- Maintain backward compatibility

### Adding New Payloads

```go
// In main.go, add to the payloads slice:
var payloads = []string{
    // ... existing payloads ...
    
    // Your new payload category
    "' YOUR_NEW_PAYLOAD --",
    
    // ... more payloads ...
}
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by SQLMap and other security testing tools
- OWASP SQL Injection Testing Guide
- Security research community

## 📞 Support

- **Email**: wwyuu799@gmail.com

## 🗺️ Roadmap

- [ ] XML/XXE injection detection
- [ ] LDAP injection tests
- [ ] Command injection detection
- [ ] Custom payload file support
- [ ] WebSocket testing
- [ ] API endpoint discovery
- [ ] Integration with CI/CD pipelines
- [ ] Docker container
- [ ] Plugin system for custom checks

## 📚 Additional Resources

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Testing for SQL Injection (OWASP)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)

---

**⭐ If you find this tool useful, please consider giving it a star on GitHub!**

**Made with ❤️ for the security community**