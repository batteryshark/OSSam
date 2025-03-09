# OSS Assessment Report: openSSL 1.1.0q

*Generated on: 2025-03-08 19:54:05*


## 📦 Package Information

- **Name:** openSSL
- **Requested Version:** 1.1.0q
- **Latest Version:** 3.4.1
- **Primary Language:** C
- **Description:** OpenSSL is a software library and command-line tool used for secure communications over computer networks. It implements the Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols and provides cryptographic functions.
- **Repository:** [https://github.com/openssl/openssl](https://github.com/openssl/openssl)
- **Maintained By:** OpenSSL Foundation and the OpenSSL Corporation

## 🗒️ Package Evaluation

- **Advisory:** ❌ Do not Use
- **Explanation:** OpenSSL 1.1.0q is no longer supported, meaning it does not receive security patches. Although specific CVEs might not directly affect it, the lack of updates makes it vulnerable to newly discovered or unpatched security issues. It is strongly recommended to upgrade to a supported version. License (Apache License 2.0) is permitted for use.

## 📜 License Evaluation

- **License:** Apache License 2.0
- **Status:** ✅ Allowed
- **Notes:** The Apache 2.0 License is permissive and allows for commercial use. It includes an express grant of patent rights from contributors to users. (Normalized from 'Apache License 2.0' to 'Apache 2.0')

## 🔒 Security Evaluation

- **Security Risk:** ❌ High
- **Risk Assessment:** OpenSSL 1.1.0q is no longer supported, meaning it does not receive security patches. Although specific CVEs might not directly affect it, the lack of updates makes it vulnerable to newly discovered or unpatched security issues. It is strongly recommended to upgrade to a supported version.

### Known Vulnerabilities:

**❓ CVE-2009-0590 (MEDIUM)**
- The ASN1_STRING_print_ex function in OpenSSL before 0.9.8k allows remote attackers to cause a denial of service.
- Status: ❌ Not affected in 1.1.0q

**❓ CVE-2009-3767 (MEDIUM)**
- OpenLDAP does not properly handle a '\0' character in a domain name in the subject's Common Name (CN) field of an X.509 certificate when OpenSSL is used.
- Status: ❌ Potentially affected indirectly through OpenLDAP

**❓ CVE-2010-0742 (HIGH)**
- The Cryptographic Message Syntax (CMS) implementation in OpenSSL before 0.9.8o and 1.x before 1.0.0a does not properly handle structures that contain OriginatorInfo.
- Status: ❌ Not affected in 1.1.0q


### Other Security Concerns:

- Timing Side Channel Attack (in versions prior to 1.1.0j)
- Denial of Service (CMS Null dereference and ChaCha20/Poly1305 heap-buffer-overflow - fixed in 1.1.0c)
- Incorrect Results (Montgomery multiplication - fixed in 1.1.0c)
- Heap Overflow Remote DOS vulnerability (CVE-2016-7054 - in version 1.1.0c)

### Repository Health:

- OpenSSL 1.1.0q is no longer supported and is not receiving security updates.
- Several vulnerabilities were identified in OpenSSL 1.1.0 and earlier versions that might also affect 1.1.0q.

## 📚 References

1. https://github.com/openssl/openssl/releases
2. https://en.wikipedia.org/wiki/OpenSSL
3. https://www.infocusp.com/blogs/openSSL-basic-tutorial/
4. https://www.openssl.org/
5. https://www.techtarget.com/whatis/definition/OpenSSL
6. https://github.com/openssl/openssl
7. https://github.com/openssl
8. https://security.stackexchange.com/questions/17947/what-are-the-implications-of-using-an-old-version-of-openssl