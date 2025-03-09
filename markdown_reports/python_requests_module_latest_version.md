# OSS Assessment Report: requests 2.32.3

*Generated on: 2025-03-08 18:52:52*


## 📦 Package Information

- **Name:** requests
- **Requested Version:** 2.32.3
- **Latest Version:** 2.32.3
- **Primary Language:** Python
- **Description:** Requests is a simple and elegant HTTP library for Python, built for human beings. It allows you to send HTTP/1.1 requests extremely easily.
- **Repository:** [https://github.com/psf/requests](https://github.com/psf/requests)
- **Maintained By:** Python Software Foundation

## 🗒️ Package Evaluation

- **Advisory:** ❗ Use with Caution
- **Explanation:** This package can be used with caution, but be aware of the following risks: Contains known vulnerabilities that may need mitigation, Has medium security risk that requires attention and Has reported security issues that need to be addressed. While the repository is actively maintained and has a large number of contributors, there are some known security vulnerabilities. CVE-2018-18074 and CVE-2024-35195 are the most concerning. Ensure the requests library is updated to at least version 2.32.0 to mitigate these risks. Other potential vulnerabilities may exist, requiring ongoing monitoring. License (Apache2) is permitted for use.

## 📜 License Evaluation

- **License:** Apache2
- **Status:** ✅ Allowed
- **Notes:** The Apache 2.0 License is permissive and allows for commercial use. It includes an express grant of patent rights from contributors to users. (Normalized from 'Apache2' to 'Apache 2.0')

## 🔒 Security Evaluation

- **Security Risk:** ⚠️ Medium
- **Risk Assessment:** While the repository is actively maintained and has a large number of contributors, there are some known security vulnerabilities. CVE-2018-18074 and CVE-2024-35195 are the most concerning. Ensure the requests library is updated to at least version 2.32.0 to mitigate these risks. Other potential vulnerabilities may exist, requiring ongoing monitoring.

### Known Vulnerabilities:

**⚠️ CVE-2018-18074 (Medium)**
- Requests package before 2.20.0 sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.
- Status: ✅ Patched in 2.20.0

**⚠️ CVE-2024-35195 (Medium)**
- If a Requests Session makes an initial request with verify=False (disabling certificate verification), all subsequent requests to the same host will continue to ignore certificate verification, regardless of later changes to the verify value.
- Status: ✅ Patched in 2.32.0


### Other Security Concerns:

- Possible other vulnerabilities listed in Snyk vulnerability database and Safety DB.

### Repository Health:

- Repository is old, but actively maintained.
- Large number of contributors, indicating good support.
- Recent commits and active development.
- CVE-2018-18074: Sending Authorization header over HTTP after HTTPS redirect.
- Versions prior to 2.32.0 vulnerable to CVE-2024-35195: Incorrect control flow may allow disabling certificate verification.

## 📚 References

1. Search results for 'python requests package'
2. Search results for 'python requests package latest version'
3. Search results for 'python requests package license'
4. Search results for 'python requests package source code'
5. Search results for 'python requests package owner'
6. https://github.com/psf/requests
7. https://security.snyk.io/package/pip/requests
8. https://app.opencve.io/cve/?vendor=python&product=requests
9. https://www.cvedetails.com/version/1371351/Python-Requests-2.31.0.html
10. https://data.safetycli.com/packages/pypi/requests/vulnerabilities
11. https://nvd.nist.gov/vuln/detail/CVE-2018-18074
12. https://docs.python-requests.org/en/latest/community/vulnerabilities.html