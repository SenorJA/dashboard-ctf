# Defensive Notes — PHP Vulnerabilities (October 2026)

> This document provides defensive guidance for the PHP vulnerabilities referenced in the
> requested repositories (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp). It is intended for
> detection, monitoring, and mitigation — **not** for exploitation.

---

## 1) GHSA-w8hw-w9fx-j79w (PHP RCE via php-cgi)
- **Summary:** Remote Code Execution in PHP-CGI under certain conditions.
- **Mitigation:**
  - Upgrade PHP to the latest stable version (≥ 8.1.30, ≥ 8.2.24, ≥ 8.3.12).
  - Disable `cgi.force_redirect` or set it to `1`.
  - Use `php-fpm` instead of `php-cgi` when possible.
  - Restrict `cgi.fix_pathinfo` to `0` in `php.ini`.
- **Detection:** Monitor for unusual CGI requests, unexpected `PATH_INFO` usage, or
  anomalous HTTP methods (e.g., `POST` to `.php` files with suspicious payloads).

## 2) GHSA-6wmf-4rv5-p3rp (PHP RCE via Windows batch files)
- **Summary:** Remote Code Execution on Windows when PHP is invoked via batch files.
- **Mitigation:**
  - Upgrade PHP to the latest stable version.
  - Avoid using batch files to invoke PHP; use direct `php.exe` or `php-cgi.exe`.
  - Validate and sanitize all input passed to batch files.
- **Detection:** Monitor for unexpected batch file executions, suspicious `.bat` file
  creation, or anomalous process spawning from PHP.

## 3) General Defensive Recommendations
- **Update PHP:** Always run the latest stable version with security patches.
- **Disable unnecessary features:** Turn off `allow_url_include`, `allow_url_fopen`,
  and `display_errors` in production.
- **Input validation:** Strictly validate and sanitize all user input.
- **Least privilege:** Run PHP with minimal necessary permissions.
- **Monitoring:** Enable detailed logging for PHP requests and errors.
- **WAF:** Use a Web Application Firewall to filter malicious requests.

## 4) SIEM Integration
- Added rule `php-suspicious` to the MIRV SIEM to alert on anomalous PHP request patterns
  (e.g., unusual headers, suspicious keywords in requests, repeated attempts from the
  same IP).
- Configure thresholds in `backend/siem.py` under `_check_php_suspicious`.

---

*Documented: 26 Oct 2026 — defensive guidance only.*
