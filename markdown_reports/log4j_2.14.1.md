# OSS Assessment Report: log4j 2.14.1

*Generated on: 2025-03-08 17:41:41*


## 📦 Package Information

- **Name:** log4j
- **Requested Version:** 2.14.1
- **Latest Version:** 2.17.1
- **Primary Language:** Java
- **Description:** Log4j is a versatile, open-source, Java-based logging framework created by the Apache Software Foundation. It records important information within a program, such as error messages and user inputs, helping developers monitor and identify potential problems. It's used across a wide range of software applications and online services.
- **Repository:** [https://git-wip-us.apache.org/repos/asf/logging-log4j2.git](https://git-wip-us.apache.org/repos/asf/logging-log4j2.git)
- **Maintained By:** Apache Software Foundation

## 🗒️ Package Evaluation

- **Advisory:** ❌ Do not Use
- **Explanation:** Log4j version 2.14.1 is vulnerable to critical remote code execution vulnerability (CVE-2021-44228), also known as Log4Shell. This vulnerability allows attackers to execute arbitrary code on affected systems. Although the repository is actively maintained, the presence of this critical vulnerability warrants a High-risk rating. License (Apache License 2.0) is permitted for use.

## 📜 License Evaluation

- **License:** Apache License 2.0
- **Status:** ✅ Allowed
- **Notes:** The Apache 2.0 License is permissive and allows for commercial use. It includes an express grant of patent rights from contributors to users. (Normalized from 'Apache License 2.0' to 'Apache 2.0')

## 🔒 Security Evaluation

- **Security Risk:** ❌ High
- **Risk Assessment:** Log4j version 2.14.1 is vulnerable to critical remote code execution vulnerability (CVE-2021-44228), also known as Log4Shell. This vulnerability allows attackers to execute arbitrary code on affected systems. Although the repository is actively maintained, the presence of this critical vulnerability warrants a High-risk rating.

### Known Vulnerabilities:

**❓ CVE-2021-44228 (CRITICAL)**
- Remote code execution vulnerability
- Status: ❌ Unpatched in version 2.14.1

**❓ CVE-2021-45046 (CRITICAL)**
- Incomplete fix for CVE-2021-44228
- Status: ❌ Unpatched in version 2.14.1

**❓ CVE-2021-45105 (MEDIUM)**
- Denial of service vulnerability
- Status: ❌ Unpatched in version 2.14.1

**❓ CVE-2021-44832 (MEDIUM)**
- Remote code execution vulnerability via JDBC Appender
- Status: ❌ Unpatched in version 2.14.1


### Repository Health:

- Vulnerable to remote code execution (CVE-2021-44228)
- Other CVEs related to denial of service and information leakage

## 📚 References

1. https://logging.apache.org/log4j/2.x/
2. https://mvnrepository.com/artifact/org.apache.logging.log4j
3. https://www.geeksforgeeks.org/apache-log4j/
4. https://logging.apache.org/log4j/2.x/manual/index.html
5. https://www.techtarget.com/whatis/feature/Log4j-explained-Everything-you-need-to-know
6. https://git-wip-us.apache.org/repos/asf/logging-log4j2.git
7. https://github.com/apache/logging-log4j2
8. https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
9. https://logging.apache.org/log4j/2.x/security.html
10. https://www.cvedetails.com/version/677194/Apache-Log4j-2.14.1.html
11. https://blog.checkpoint.com/security/protecting-against-cve-2021-44228-apache-log4j2-versions-2-14-1/
12. https://www.cisa.gov/news-events/alerts/2021/12/13/cisa-creates-webpage-apache-log4j-vulnerability-cve-2021-44228
13. https://blog.cloudflare.com/inside-the-log4j2-vulnerability-cve-2021-44228/
14. https://community.citrix.com/articles/security/guidance-for-reducing-apache-log4j-security-vulnerability-risk-with-citrix-waf-cve-2021-44228cve-2021-45046cve-2021-45105-r283/
15. https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
16. https://www.cyber.gc.ca/en/alerts/active-exploitation-apache-log4j-vulnerability