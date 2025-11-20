# 🔓 Information Disclosure Vulnerabilities - Testing Guide

## 📋 Table of Contents

1. Error Message Disclosure
2. Debug Page Exposure
3. Source Code & Backup Files
4. Authentication Bypass via Headers
5. Version Control History
6. Detection & Mitigation

---

## ⚠️ Educational Notice

**Purpose:** This guide is for authorized security testing, bug bounty programs, and educational purposes only. Always obtain proper authorization before testing any system.

---

## 🚨 What is Information Disclosure?

**Information Disclosure** occurs when a website unintentionally reveals sensitive information to users. This can include:

- 🔑 Credentials and API keys
- 📁 Internal file paths and directory structures
- 🗄️ Database information and queries
- 🔧 Technology stack and version numbers
- 📝 Source code and configuration files
- 🔐 Session tokens and authentication details

**Impact:** Can lead to further attacks and complete system compromise

---

## 1️⃣ Information Disclosure in Error Messages

### 🎯 Vulnerability Description

Websites may display detailed error messages containing sensitive information like:

- Database connection strings
- Internal file paths
- Technology versions
- SQL query structure
- Stack traces

### 🔍 Testing Methodology

#### Trigger Error Messages

**Method 1: SQL Injection Characters**

```
# Add single quote to parameters
https://example.com/product?id=1'

# Common error triggers
' OR 1=1--
" OR "1"="1
'; DROP TABLE--
```

**Method 2: Extreme Values**

```
# Large numbers to cause overflow
https://example.com/product?id=999999999999

# Negative values
https://example.com/product?id=-1

# Special characters
https://example.com/search?q=<script>

# Unicode characters
https://example.com/input?data=%00
```

**Method 3: Type Confusion**

```
# String instead of integer
https://example.com/product?id=abc

# Array instead of string
https://example.com/product?id[]=1&id[]=2

# Null bytes
https://example.com/file?name=file%00.txt
```

### 📊 What to Look For

- ✅ Database error messages (MySQL, PostgreSQL, MSSQL)
- ✅ File path disclosure (e.g., `/var/www/html/`)
- ✅ Framework version numbers (Laravel, Django, etc.)
- ✅ Stack traces with function calls
- ✅ Configuration details

### 🛡️ Impact

**Severity:** 🟡 Medium to 🔴 High

**Risks:**

- Reveals technology stack for targeted attacks
- Exposes file system structure
- Provides SQL injection attack vectors
- Leaks sensitive configuration data

---

## 2️⃣ Information Disclosure on Debug Pages

### 🎯 Vulnerability Description

Debug pages, admin panels, or development endpoints accidentally exposed in production environments.

### 🔍 Testing Methodology

#### Using Burp Suite Site Map

**Step 1: Configure Burp Suite**

```
1. Navigate through the target website normally
2. Open Burp Suite → Target → Site Map
3. Expand the target website URL tree
4. Look for unusual or sensitive paths
```

**Step 2: Identify Sensitive Endpoints** Look for paths like:

```
/debug
/debug.php
/admin
/phpinfo.php
/test
/dev
/config
/console
/swagger
/api-docs
/.env
/health
/metrics
```

#### Manual URL Fuzzing

**Common Debug Paths:**

```
https://example.com/debug
https://example.com/trace
https://example.com/console
https://example.com/server-status
https://example.com/phpinfo.php
https://example.com/info.php
https://example.com/test.php
```

**Framework-Specific Paths:**

```
# Django
/_debug_toolbar/
/admin/

# Laravel
/telescope/
/horizon/

# Spring Boot
/actuator/
/actuator/env
/actuator/health

# Node.js
/debug/
/swagger-ui.html
```

### 📊 Information Found on Debug Pages

- 🔧 Environment variables
- 🗄️ Database credentials
- 🔑 API keys and secrets
- 📊 System configuration
- 🌐 Internal IP addresses
- 📝 Application logs

### 🛡️ Impact

**Severity:** 🔴 High to Critical

**Risks:**

- Direct access to credentials
- System configuration exposure
- Potential RCE through debug consoles
- Complete system compromise

---

## 3️⃣ Source Code Disclosure via Backup Files

### 🎯 Vulnerability Description

Backup files, temporary files, or configuration files left accessible on web servers.

### 🔍 Testing Methodology

#### Directory Enumeration

**Tools to Use:**

```bash
# Gobuster
gobuster dir -u https://example.com -w /path/to/wordlist.txt

# Dirb
dirb https://example.com /usr/share/wordlists/dirb/common.txt

# ffuf
ffuf -u https://example.com/FUZZ -w wordlist.txt

# wfuzz
wfuzz -c -z file,wordlist.txt https://example.com/FUZZ
```

#### Common Backup File Patterns

**File Extensions:**

```
.bak
.backup
.old
.tmp
.temp
.swp
.swo
.save
.copy
~
.orig
.dist
```

**Common Backup Files:**

```
index.php.bak
config.php.old
database.sql.bak
backup.zip
backup.tar.gz
site.zip
www.tar.gz
```

#### Configuration Files

**Look for:**

```
.env
.env.backup
config.php
config.yml
settings.py
web.config
application.properties
database.yml
credentials.json
secrets.json
```

#### Version Control Exposure

**Check for exposed VCS directories:**

```
/.git/
/.svn/
/.hg/
/.bzr/
/CVS/
```

**Test Commands:**

```bash
# Check if .git is exposed
curl https://example.com/.git/HEAD

# Check for .svn
curl https://example.com/.svn/entries

# Check for .env file
curl https://example.com/.env
```

### 📊 What to Look For

- 🔑 **Credentials:** Database passwords, API keys
- 📝 **Source Code:** PHP, Python, Java files
- 🗄️ **Database Dumps:** SQL files with data
- 🔧 **Configuration:** Server settings, paths
- 🗺️ **Directory Structure:** Internal architecture

### 🛡️ Impact

**Severity:** 🔴 High to Critical

**Risks:**

- Complete source code access
- Hardcoded credentials
- Business logic exposure
- Database structure revelation

---

## 4️⃣ Authentication Bypass via Information Disclosure

### 🎯 Vulnerability Description

HTTP TRACE method or other misconfigurations reveal custom authentication headers.

### 🔍 Testing Methodology

#### Using TRACE Method

**What is TRACE?**

- HTTP method designed for debugging
- Echoes back received request
- Can reveal headers added by proxies/load balancers

**Testing Steps:**

**Step 1: Test TRACE on Admin Endpoint**

```http
TRACE /admin HTTP/1.1
Host: example.com
```

**Step 2: Analyze Response** Look for custom headers like:

```http
X-Custom-IP-Authorization: 127.0.0.1
X-Admin-Token: abc123
X-Forwarded-For: 192.168.1.1
X-Real-IP: 10.0.0.1
```

**Step 3: Use Discovered Header**

```http
GET /admin HTTP/1.1
Host: example.com
X-Custom-IP-Authorization: 127.0.0.1
```

#### Other HTTP Methods to Test

```http
# OPTIONS - Shows allowed methods
OPTIONS /admin HTTP/1.1
Host: example.com

# HEAD - May reveal different info
HEAD /admin HTTP/1.1
Host: example.com

# DEBUG (non-standard)
DEBUG /admin HTTP/1.1
Host: example.com
```

### 📊 Headers That May Be Disclosed

**Authentication Headers:**

```
X-Custom-IP-Authorization
X-Admin-Key
X-Auth-Token
X-API-Key
Authorization
```

**IP-Based Headers:**

```
X-Forwarded-For
X-Real-IP
X-Originating-IP
X-Remote-IP
X-Client-IP
```

### 🛡️ Impact

**Severity:** 🔴 High

**Risks:**

- Bypass authentication mechanisms
- Access admin panels
- Privilege escalation
- Unauthorized access

---

## 5️⃣ Information Disclosure in Version Control History

### 🎯 Vulnerability Description

Exposed `.git` directories allow downloading entire repository history, including deleted sensitive data.

### 🔍 Testing Methodology

#### Step 1: Check for .git Exposure

```bash
# Test if .git directory is accessible
curl https://example.com/.git/HEAD

# Check for common .git files
curl https://example.com/.git/config
curl https://example.com/.git/index
```

#### Step 2: Download Entire Repository

**Using wget:**

```bash
# Download entire .git directory
wget -r https://example.com/.git/

# Alternative with better handling
wget --mirror --no-parent https://example.com/.git/
```

**Using Git Tools:**

```bash
# GitDumper (specialized tool)
git clone https://github.com/arthaud/git-dumper.git
python3 git-dumper.py https://example.com/.git/ output_dir/

# dvcs-ripper
./rip-git.pl -v -u https://example.com/.git/
```

#### Step 3: Analyze Git History

**Using Git Cola (GUI):**

```
1. Open Git Cola application
2. File → Open Git Repository
3. Select downloaded .git directory
4. View → Commit → Undo Last Commit
5. Examine deleted files and changes
```


```

**Common Sensitive Files:**

```
.env
config.php
database.yml
secrets.json
credentials.json
id_rsa (SSH keys)
*.pem
*.key
```

### 📊 Information Found in Git History

- 🔑 **Deleted API keys and tokens**
- 🗄️ **Database credentials**
- 📧 **Email addresses**
- 🔐 **SSH private keys**
- 🎯 **Internal URLs and endpoints**
- 💼 **Business logic and algorithms**

### 🛡️ Impact

**Severity:** 🔴 Critical

**Risks:**

- Complete source code exposure
- Historical credentials still valid
- All deleted secrets accessible
- Full development history visible

---

## 🔍 Detection & Testing Tools

### Automated Scanners

**Directory Enumeration:**

```bash
# Gobuster
gobuster dir -u https://target.com -w wordlist.txt -x php,bak,old

# Dirsearch
python3 dirsearch.py -u https://target.com -e php,bak,zip

# Feroxbuster
feroxbuster -u https://target.com -w wordlist.txt
```

**Git Repository Tools:**

```bash
# git-dumper
python3 git-dumper.py https://target.com/.git/ output/

# GitHack
python GitHack.py https://target.com/.git/

# dvcs-ripper
./rip-git.pl -v -u https://target.com/.git/
```

**HTTP Method Testing:**

```bash
# Nmap HTTP Methods script
nmap --script http-methods target.com

# cURL manual testing
curl -X TRACE https://target.com/admin
curl -X OPTIONS https://target.com/admin
```

### Manual Testing Checklist

- [ ] Test error handling with malformed inputs
- [ ] Check for exposed debug endpoints
- [ ] Enumerate directories for backup files
- [ ] Test HTTP methods (TRACE, OPTIONS, DEBUG)
- [ ] Check for .git, .svn, .env exposure
- [ ] Review all HTTP responses for information leakage
- [ ] Test different user roles for information differences
- [ ] Check response headers for sensitive data
- [ ] Look for commented-out code in HTML/JS

---

## 🛡️ Mitigation Strategies

### For Developers

#### 1. Error Handling

```php
// ❌ Bad - Detailed errors in production
catch (Exception $e) {
    echo $e->getMessage();
}

// ✅ Good - Generic errors in production
catch (Exception $e) {
    error_log($e->getMessage()); // Log internally
    echo "An error occurred. Please try again.";
}
```

#### 2. Debug Mode Configuration

```python
# Django settings.py
# ❌ Bad
DEBUG = True

# ✅ Good
DEBUG = False  # In production
ALLOWED_HOSTS = ['your-domain.com']
```

#### 3. File Access Control

```nginx
# Nginx - Block sensitive files
location ~ /\. {
    deny all;
}

location ~* \.(bak|backup|old|tmp|swp)$ {
    deny all;
}
```

#### 4. Disable HTTP TRACE

```apache
# Apache
TraceEnable off

# Nginx
if ($request_method = TRACE) {
    return 405;
}
```

#### 5. Git Security

```bash
# Never commit sensitive files
echo ".env" >> .gitignore
echo "config.php" >> .gitignore
echo "*.key" >> .gitignore

# Remove sensitive data from history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch .env" \
  --prune-empty --tag-name-filter cat -- --all
```

### Security Best Practices

✅ **Do:**

- Use generic error messages in production
- Disable debug mode in production
- Implement proper logging
- Remove backup files from web root
- Use `.gitignore` properly
- Disable unnecessary HTTP methods
- Implement proper access controls
- Regular security audits
- Use environment variables for secrets

❌ **Don't:**

- Display stack traces to users
- Leave debug endpoints accessible
- Commit credentials to version control
- Keep backup files in web directory
- Allow directory listing
- Use default configurations
- Expose framework versions
- Leave commented-out sensitive code

---

## 📊 Vulnerability Severity Matrix

|Vulnerability Type|Severity|CVSS Range|Impact|
|---|---|---|---|
|Git Repository Exposure|🔴 Critical|9.0-10.0|Complete source + secrets|
|Debug Console Exposed|🔴 Critical|8.5-9.5|RCE potential|
|Credentials in Errors|🔴 High|7.5-8.5|Direct credential access|
|Backup File Exposure|🔴 High|7.0-8.0|Source code + config|
|TRACE Method Disclosure|🟡 Medium|5.0-6.0|Header information|
|Version Disclosure|🟡 Low-Medium|3.0-4.0|Targeted attack info|

---

## 🧪 Practice Labs

### Recommended Platforms

- **PortSwigger Web Security Academy** (Free)
- **HackTheBox**
- **TryHackMe**
- **OWASP WebGoat**
- **PentesterLab**

### Lab Exercises

**Lab 1: Error Message Exploitation**

1. Trigger SQL errors with special characters
2. Identify database type from error messages
3. Extract file paths from stack traces

**Lab 2: Directory Enumeration**

1. Use Gobuster to find backup files
2. Access `.git` repository
3. Extract credentials from config files

**Lab 3: Git History Analysis**

1. Download exposed `.git` directory
2. Use git commands to find deleted secrets
3. Extract API keys from commit history

---

## 💡 Real-World Examples

### Case Study 1: API Key in Git History

```
Severity: Critical
Finding: AWS credentials committed then deleted
Impact: $70,000 in unauthorized cloud usage
Lesson: Secrets in git history remain accessible
```

### Case Study 2: Debug Page Exposure

```
Severity: High
Finding: /debug endpoint exposed in production
Impact: Full database credentials disclosed
Lesson: Disable debug features in production
```

### Case Study 3: Backup File Download

```
Severity: High
Finding: database.sql.bak publicly accessible
Impact: Complete customer data breach
Lesson: Remove backup files from web root
```

---

## 🎓 Additional Resources

### Tools

- **GitTools:** https://github.com/internetwache/GitTools
- **TruffleHog:** Scan git history for secrets
- **GitLeaks:** Find secrets in git repos
- **Gobuster:** Directory enumeration
- **Burp Suite:** Web proxy and scanner

### Reading Material

- OWASP Top 10 - Security Misconfiguration
- CWE-209: Information Exposure Through Error Messages
- CWE-538: Insertion of Sensitive Information Into Externally-Accessible File

---

_Remember: This guide is for authorized security testing only. Always obtain proper permission before testing any system. Report vulnerabilities responsibly._ 🔐