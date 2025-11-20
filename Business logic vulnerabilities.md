# 🔐 Business Logic Vulnerabilities

## 1️⃣ Excessive Trust in Client-Side Controls 🎯

> ⚠️ When websites trust client-side resources without proper sanitization

### 🔍 Attack Steps:
1. 🎯 Find requests with changeable parameters (e.g., price)
2. 🔧 Modify parameters and send request
3. 👀 Observe if changes are accepted

---

## 2️⃣ High-Level Logic Vulnerability 💰

> 🎭 When websites hide basic changeable parameters like price

### 🔍 Attack Steps:
1. ➕ Add target item (e.g., jacket $1300)
2. ➖ Add another item in **negative value**
3. 🔢 Calculate: Add $100 item 12-13 times in negative to balance
4. 💸 Exploit the money limit loophole

---

## 3️⃣ Inconsistent Security Controls 📧

> 🚨 Excessive data exposure to client-side (e.g., admin email patterns)

### 🔍 Attack Scenario:
**Example:** Website exposes insider email pattern `@dontwannacry.com`

### 📋 Steps:
1. 📝 Register with normal account
2. ✅ Login after verification
3. 🔄 Update email to `attacker@dontwannacry.com`
4. 🎉 Website grants admin functionality

---

## 4️⃣ Flawed Enforcement of Business Rules 🎟️

> ⚙️ Website doesn't check proper record of coupons or client-side functionality

### 🔍 Basic Exploitation:
1. 🎫 Use 2 coupons
2. 🔁 Apply them in sequence (one by one)
3. ✨ Observe if it works

### ⚡ Advanced: Race Condition
- 🚀 Send same request multiple times **simultaneously**
- 🤯 Server gets confused and processes some requests
- 📊 Example: 100 requests → 20-65 may be processed

---

## 5️⃣ Low-Level Logic Flaw 🔢

> 🚫 No limitation on orders → Negative amount exploitation

### 🔍 Attack Steps:
1. 📤 Send request to Repeater
2. 🔧 Set quantity to `99$$` (null payload)
3. ⚙️ Set maximum concurrent to 1
4. 🔄 Refresh until you see **negative number**
5. ➕ Add more items to decrease negative value → near $0
6. 🧮 Calculate and purchase item

---

## 6️⃣ Inconsistent Handling of Exceptional Input ✂️

> 📏 No validation from client-side, but trimming after login

### 🔍 Attack Vector:
**Scenario:** Admin panel visible only to `@dontwannacry` email users

### 📋 Steps:
1. 🔍 Identify parameter (email field)
2. 🎯 Send to Intruder with character blocks (100-500, step 100)
3. ✅ Verify account and login
4. 🔍 Observe trim defense (255 character limit)
5. 🎭 Craft payload:
   ```
   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dontwannacry.com.exploit-server.net
   ```
6. ✂️ Defense trims to `@dontwannacry.com`
7. 🎉 Access admin panel + verification emails sent to your server

---

## 7️⃣ Weak Isolation on Dual-Use Endpoint 🔑

> 🚪 Extra parameters can be edited/removed without validation

### 🔍 Attack Steps:
1. 👤 Login as regular user
2. 🔒 Navigate to password change
3. 🔍 Notice **username field** (shouldn't exist!)
4. 🎯 Input: `administrator` username
5. ❌ Leave current password blank (or remove parameter)
6. 🆕 Set new password
7. ✅ If no validation → administrator password changed!

---

## 8️⃣ Insufficient Workflow Validation 🔄

> ⚠️ Website doesn't check sequence/flow of requests

### 🔍 Attack Steps:
1. 🛒 Purchase cheap item
2. 👀 Observe request sequence
3. 📤 Send confirmation request to Repeater
4. 🎯 Add expensive item to cart
5. ⚡ **Before placing order** → Send confirmation request
6. 🎉 Order placed without payment!

---

## 9️⃣ Authentication Bypass via Flawed State Machine 🎭

> 🔓 Website doesn't verify all authentication steps

### 🔍 Attack Steps:
1. 🔛 Turn on Intercept
2. 🔑 Login with normal credentials
3. ⏭️ Forward requests
4. 🚫 **Drop** role selector request
5. 🔄 Reload website with Intercept off
6. 🎉 Default role assigned = **Admin**

---

## 🔟 Infinite Money Flaw 💳

> 🔁 Gift card + coupon loop creates infinite store credit

### 🔍 Detailed Steps:

#### Initial Setup:
1. 🔑 Login and signup for newsletter → Get `SIGNUP30` coupon
2. 💳 Add $10 gift card to basket
3. 🎟️ Apply 30% discount coupon at checkout
4. ✅ Complete order and copy gift card code
5. 🔄 Redeem gift card → Gain $3 store credit

#### 🤖 Automation with Burp Macro:
6. ⚙️ Settings → Sessions → Add Rule
7. 🌐 Scope: Include all URLs
8. ➕ Rule Actions → Run a macro → Add

**Macro Sequence:**
```
POST /cart
POST /cart/coupon
POST /cart/checkout
GET /cart/order-confirmation?order-confirmed=true
POST /gift-card
```

9. 🔧 Configure `GET /cart/order-confirmation`:
   - Create custom parameter: `gift-card`
   - Highlight gift card code in response

10. 🔧 Configure `POST /gift-card`:
    - Set `gift-card` parameter from prior response

11. 🧪 Test macro to verify functionality
12. 📤 Send `GET /my-account` to Intruder
13. 🎯 Payload: Null payloads (412 iterations)
14. ⚙️ Resource pool: Max concurrent = 1
15. 🚀 Start attack → Gain enough credit for jacket!

---

## 1️⃣1️⃣ Authentication Bypass via Encryption Oracle 🔐

> 🔓 Exploiting encrypted cookies through encryption/decryption oracle

### 🔍 Attack Steps:

#### Discovery Phase:
1. 🔑 Login with "Stay logged in" + post comment
2. 📧 Use invalid email → Notice encrypted `notification` cookie
3. 👀 Error reflects: `Invalid email address: your-invalid-email`
4. 💡 Realize notification cookie contains decrypted data

#### Setup Encrypt/Decrypt Requests:
5. 📤 Send `POST /post/comment` and `GET /post?postId=x` to Repeater
6. 🏷️ Rename tabs: "encrypt" and "decrypt"

#### Decrypt Stay-Logged-In Cookie:
7. 📋 Copy `stay-logged-in` cookie → Paste into `notification` cookie
8. 🔓 Decrypt reveals format: `wiener:1598530205184` (username:timestamp)
9. 📝 Copy timestamp

#### Craft Admin Cookie:
10. ✍️ Encrypt: `administrator:your-timestamp`
11. 📋 Copy new notification cookie
12. 🔓 Decrypt and observe 23-char prefix: `Invalid email address: `
13. 🛠️ Send to Decoder → URL decode → Base64 decode
14. ✂️ Hex tab: Delete first 23 bytes
15. ⚠️ Error: Block cipher requires multiple of 16 bytes

#### Padding Attack:
16. ➕ Add 9 padding characters: `xxxxxxxxxadministrator:your-timestamp`
17. 🔐 Encrypt and test decryption
18. 🛠️ Decode → Delete **32 bytes** → Re-encode
19. ✅ Verify output: `administrator:your-timestamp` (no prefix)

#### Final Exploit:
20. 📋 Copy decrypted admin cookie
21. 🌐 Browser → Storage → Paste into `stay-logged-in` cookie
22. 🗑️ Remove session cookie
23. 🎉 Access admin panel!

---

## 1️⃣2️⃣ Bypassing Access Controls via Email Parsing Discrepancies 📧

> 🎭 Exploiting email encoding to bypass domain restrictions

### 🔍 Email Encoding Background:

#### 🏷️ Encoded-Word Format:
```
=?<charset>?<encoding>?<encoded-text>?=
```

**Components:**
- `=?` → Start marker
- `<charset>` → UTF-7, UTF-8, ISO-8859-1, etc.
- `<encoding>` → q-encoding, base64, etc.
- `<encoded-text>` → Encoded values
- `?=` → End marker

### 🧪 Testing Different Encodings:

#### ❌ ISO-8859-1 (Blocked):
```
=?iso-8859-1?q?=61=62=63?=foo@ginandjuice.shop
```
- `=61` → a, `=62` → b, `=63` → c (ASCII values)
- ⛔ Error: "Registration blocked for security reasons"

#### ❌ UTF-8 (Blocked):
```
=?utf-8?q?=61=62=63?=foo@ginandjuice.shop
```
- Same ASCII encoding method
- ⛔ Same error message

#### ✅ UTF-7 (Success!):
```
=?utf-7?q?&AGEAYgBj-?=foo@ginandjuice.shop
```
- Uses Base64: `+AGEAYgBj-` (+ replaced with &)
- ✨ No error → Bypass detected!

### 🎯 Exploitation:

#### Craft Malicious Email:
```
=?utf-7?q?attacker&AEA-[YOUR-EXPLOIT-SERVER]&ACA-?=@ginandjuice.shop
```

**Encoding Key:**
- `&AEA-` → `@` symbol
- `&ACA-` → Space character

#### 🔍 How It Works:

**Server Processing:**
```
attacker@[EXPLOIT-SERVER] @ginandjuice.shop
                          ↑
                      Space here!
```

1. ✅ **Validation:** Sees `@ginandjuice.shop` → Approved!
2. 📧 **Email Service:** Sends to `attacker@exploit-server.net` (ignores after space)
3. 🎉 **Result:** Admin access + verification email to your server!

### 💡 Why UTF-7 Works:
- ⚠️ Server doesn't recognize UTF-7 as security threat
- 🎭 Less common encoding bypasses validation
- 🔓 Tricks domain validation while redirecting emails

---

## 📚 Key Takeaways

### 🛡️ Common Themes:
- ❌ Insufficient validation
- 🎭 Client-side trust
- 🔓 State machine flaws
- 📧 Input handling issues
- 🔄 Workflow bypasses

### 🔍 Testing Methodology:
1. 🕵️ Identify business logic flows
2. 🧪 Test edge cases
3. 🔧 Manipulate parameters
4. 🔁 Test sequence violations
5. 🎯 Exploit trust boundaries

---

> ⚠️ **Disclaimer:** These techniques are for educational purposes and authorized security testing only. Unauthorized access is illegal.