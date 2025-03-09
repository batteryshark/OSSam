# OSS Assessment Report: GraalVM 24.1.2

*Generated on: 2025-03-08 18:05:17*


## 📦 Package Information

- **Name:** GraalVM
- **Requested Version:** 24.1.2
- **Latest Version:** 24.1.2
- **Primary Language:** Java
- **Description:** GraalVM is a high-performance JDK distribution designed to accelerate the execution of applications written in Java and other JVM languages, along with support for languages like JavaScript, Python, and Ruby. It includes an advanced optimizing compiler and allows compiling Java applications into standalone native binaries.
- **Repository:** [https://github.com/oracle/graal](https://github.com/oracle/graal)
- **Maintained By:** Oracle

## 🗒️ Package Evaluation

- **Advisory:** ❌ Do not Use
- **Explanation:** The package has been rated as High risk because it has multiple high severity vulnerabilities (CVEs). The presence of high severity vulnerabilities significantly increases risk. License (GraalVM Free Terms and Conditions (GFTC)) requires legal approval.

## 📜 License Evaluation

- **License:** GraalVM Free Terms and Conditions (GFTC)
- **Status:** ⚠️ Requires Legal Approval
- **Notes:** This license type is not in the common license list and requires legal review.

> **Action Required:** This license requires legal approval before use.

## 🔒 Security Evaluation

- **Security Risk:** ❌ High
- **Risk Assessment:** The package has been rated as High risk because it has multiple high severity vulnerabilities (CVEs). The presence of high severity vulnerabilities significantly increases risk.

### Known Vulnerabilities:

**❓ CVE-2019-2813 (HIGH)**
- Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise Oracle GraalVM Enterprise Edition.
- Status: ❌ Modified

**❓ CVE-2019-2862 (MEDIUM)**
- Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle GraalVM Enterprise Edition.
- Status: ❌ Modified

**❓ CVE-2019-2986 (HIGH)**
- Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise Oracle GraalVM Enterprise Edition.
- Status: ❌ Modified


### Repository Health:

- Multiple high severity CVEs exist
- CVEs affect GraalVM Enterprise Edition
- Repository is relatively young (created around 2016)

## 📚 References

1. https://www.graalvm.org/
2. https://en.wikipedia.org/wiki/GraalVM
3. https://github.com/oracle/graal
4. https://www.oracle.com/java/graalvm/
5. https://www.graalvm.org/faq/
6. N/A
7. http://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html
8. http://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html