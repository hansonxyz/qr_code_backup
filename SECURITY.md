# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in QR Code Backup, please report it responsibly:

### How to Report

1. **Email**: Send details to [SECURITY_EMAIL_HERE] with subject "Security Vulnerability in QR Code Backup"

2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if you have one)
   - Your contact information

3. **Response Time**:
   - We will acknowledge receipt within **48 hours**
   - We will provide a detailed response within **7 days**
   - We will keep you informed of progress toward a fix

### What to Expect

- **Confidentiality**: Your report will be kept confidential
- **Credit**: You will be credited in the security advisory (unless you prefer otherwise)
- **Coordination**: We will coordinate disclosure timeline with you
- **Fix**: We will work on a fix and release it as soon as possible

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :x:                |

## Security Model

### Threat Model

**What QR Code Backup Protects Against:**

✅ **Physical theft of printed backups**
- Encrypted backups are protected with AES-256-GCM
- Encryption happens before QR encoding (printed codes contain ciphertext)

✅ **Unauthorized access to backup data**
- Strong password-based encryption with Argon2id
- Memory-hard KDF prevents brute-force attacks (64MB RAM per attempt)

✅ **Tampering with backup data**
- Authenticated encryption (GCM) detects modifications
- MD5 checksums verify data integrity

✅ **Data corruption**
- QR error correction (7-30%) handles physical damage
- Reed-Solomon parity (5% default) recovers missing pages
- Triple layer of protection

**What QR Code Backup Does NOT Protect Against:**

❌ **Physical compromise of the password**
- If attacker obtains your password, encryption provides no protection
- Store passwords securely and separately from backups

❌ **Quantum computers (future threat)**
- AES-256-GCM is quantum-resistant for symmetric encryption
- However, Grover's algorithm reduces effective strength to ~AES-128
- This is still considered secure as of 2024

❌ **Rubber-hose cryptanalysis**
- Coerced password disclosure defeats encryption
- Consider using plausible deniability schemes if this is a concern

❌ **Side-channel attacks on the decoding device**
- If attacker controls the device you use to decode, they may capture the password
- Use trusted, secure devices for decryption

❌ **Complete destruction of all backup copies**
- Paper can burn, flood, or deteriorate beyond recovery
- Store multiple copies in different physical locations

### Security Features

#### Encryption (AES-256-GCM)

**Algorithm**: AES-256-GCM (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode)

**Properties**:
- **Confidentiality**: Ciphertext reveals nothing about plaintext
- **Authentication**: Tampering is automatically detected
- **Quantum-resistant**: Secure against known quantum algorithms (as of 2024)

**Implementation**: Uses `cryptography` library (pyca/cryptography)
- Industry-standard implementation
- Audited and maintained
- FIPS-compliant

#### Key Derivation (Argon2id)

**Algorithm**: Argon2id (winner of Password Hashing Competition 2015)

**Properties**:
- **Memory-hard**: Requires 64MB RAM per attempt (configurable)
- **GPU/ASIC resistant**: Cannot be accelerated by specialized hardware
- **Side-channel resistant**: Hybrid of Argon2i (side-channel resistant) and Argon2d (GPU resistant)

**Parameters** (hardcoded for security):
- Time cost: 3 iterations
- Memory cost: 65536 KiB (64 MB)
- Parallelism: 4 threads

**Implementation**: Uses `argon2-cffi` library
- Python bindings to official Argon2 C implementation
- Constant-time password comparison

#### Password Verification (BLAKE2b)

**Algorithm**: BLAKE2b (fast cryptographic hash)

**Purpose**: Fast password pre-check before expensive decryption attempt

**Properties**:
- **Fast**: Faster than SHA-2, SHA-3
- **Secure**: No known vulnerabilities
- **Constant-time comparison**: Prevents timing attacks

#### Parity Recovery (Reed-Solomon)

**Algorithm**: Reed-Solomon erasure codes

**Purpose**: Recover missing data pages

**Properties**:
- Can recover N missing pages with N parity pages
- Does not leak plaintext (computed on ciphertext)
- Works at chunk level (complements QR error correction)

**Implementation**: Uses `reedsolo` library

### Known Limitations

1. **Password strength entirely user-dependent**
   - Weak passwords can be brute-forced despite Argon2id
   - Recommendation: Use strong passphrases (4+ random words, or 16+ random characters)

2. **No protection against keyloggers on decoding device**
   - Use trusted, malware-free devices for decryption
   - Consider hardware password managers

3. **MD5 used for document validation (not security)**
   - MD5 is cryptographically broken for collision resistance
   - We use it only for document identification, not security
   - Tampering is detected by GCM authentication tag

4. **No forward secrecy**
   - If password is compromised, all backups encrypted with it are compromised
   - Use different passwords for different backups if this is a concern

5. **Metadata not encrypted**
   - Page numbers, encryption status, Argon2 parameters visible in QR codes
   - Only the data itself is encrypted

## Security Best Practices

### For Users

1. **Use strong passwords**:
   - Minimum 16 characters
   - Use a passphrase (e.g., "correct horse battery staple banana elephant")
   - Use a password manager

2. **Store passwords separately**:
   - Never store password with encrypted backup
   - Use different physical locations
   - Consider Shamir's Secret Sharing to split password

3. **Test recovery immediately**:
   - Decode backup right after creating it
   - Verify you can decrypt with your password
   - Don't wait until you need it

4. **Use high error correction for critical data**:
   ```bash
   qr-backup encode secrets.txt --encrypt --error-correction H --parity-percent 10.0
   ```

5. **Store multiple copies in different locations**:
   - Home safe
   - Off-site location (safety deposit box)
   - Trusted family member

6. **Verify integrity regularly**:
   - Periodically scan and decode backups
   - Check MD5 checksums match
   - Replace degraded copies

### For Contributors

1. **Never commit secrets**:
   - No API keys, passwords, or private keys in code
   - Use `.gitignore` to exclude sensitive files

2. **Validate all inputs**:
   - Sanitize file paths
   - Validate user input
   - Check bounds and limits

3. **Use constant-time comparisons for secrets**:
   - Never use `==` for password comparison
   - Use `secrets.compare_digest()` or equivalent

4. **Keep dependencies updated**:
   - Monitor for security advisories
   - Update cryptographic libraries promptly
   - Run `pip list --outdated` regularly

5. **Follow secure coding practices**:
   - Principle of least privilege
   - Fail securely (don't leak information in errors)
   - Clear sensitive data from memory when done

## Security Advisories

Security advisories will be published at:
- GitHub Security Advisories: [REPO_URL/security/advisories]
- CHANGELOG.md (under "Security" section)

## Cryptographic Dependencies

| Library | Purpose | Version | Last Audit |
|---------|---------|---------|------------|
| cryptography | AES-256-GCM | ≥41.0.0 | [pyca.io](https://cryptography.io) |
| argon2-cffi | Argon2id KDF | ≥23.1.0 | Official Argon2 bindings |
| reedsolo | Reed-Solomon | ≥1.7.0 | - |

We use well-established, audited cryptographic libraries. We do not implement custom cryptography.

## Responsible Disclosure

We follow the principle of responsible disclosure:

1. **Private report** to maintainers
2. **Develop fix** in private
3. **Coordinate disclosure** with reporter
4. **Public disclosure** after fix is available
5. **Credit reporter** in security advisory

Thank you for helping keep QR Code Backup secure! 🔒
