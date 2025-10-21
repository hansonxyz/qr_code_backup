# QR Code Backup

**Archive digital data as printable QR codes for long-term offline storage.**

A command-line tool that converts any file into a PDF full of QR codes that you can print and store physically. When you need your data back, just scan the pages and decode—even if they're out of order or some pages are missing.

[![Tests](https://img.shields.io/badge/tests-45%20passing-brightgreen)]() [![License](https://img.shields.io/badge/license-MIT-blue)]() [![Python](https://img.shields.io/badge/python-3.8%2B-blue)]()

---

## Overview

Digital storage fails. Hard drives crash, cloud services shut down, formats become obsolete. But paper, stored properly, can last centuries.

**QR Code Backup** encodes your critical files—encryption keys, documents, passwords, certificates—into QR codes on paper. It's designed for the long haul: built-in encryption, automatic error recovery, and resilience against physical damage.

Think of it as **tar for paper archives**.

### Why Use This?

- **🔒 Offline & Air-Gapped** - No network, no cloud, completely offline storage
- **🛡️ Survives Digital Failures** - Independent of hard drives, USB sticks, or online services
- **📜 Long-Term Archival** - Paper stored properly outlasts digital media (decades to centuries)
- **🔐 Built-in Encryption** - Military-grade AES-256-GCM with password protection
- **🔧 Self-Recovering** - Automatic recovery from missing or damaged pages
- **🎯 Physical Control** - You control the medium, no third-party dependencies

---

## Key Features

### Core Functionality
- **📄 Any File → QR Codes** - Encode any file type into multi-page PDF documents
- **🔄 Perfect Reconstruction** - Decode scanned PDFs back to exact original file
- **✅ Automatic Verification** - MD5 checksums ensure data integrity

### Robustness & Recovery
- **🆘 Parity Pages** - Always-on Reed-Solomon erasure codes (default 5% overhead)
  - Automatically recover missing pages
  - Works like RAID for paper - lose pages, still get your data back
- **🔀 Order-Independent** - Scan pages in any order, automatic reordering
- **🚨 Mixed Document Detection** - Prevents accidental page mixing from different backups
- **🛡️ Built-in Error Correction** - QR codes with 7-30% error correction handle physical damage

### Security
- **🔐 AES-256-GCM Encryption** - Quantum-resistant symmetric encryption
- **🔑 Argon2id Key Derivation** - Memory-hard, GPU/ASIC resistant password hashing
- **✓ Authenticated Encryption** - Automatic tampering detection

### Optimization
- **🗜️ Automatic Compression** - bzip2 compression maximizes storage efficiency
- **⚙️ Configurable Density** - Adjust QR code size for your printer/scanner
- **📊 Professional Output** - Headers with page numbers and decode instructions

---

## Practical Use Cases

### Security & Critical Data
- **🔑 Encryption Key Backup** - Store PGP keys, SSH keys, Bitcoin wallets offline
- **🔒 Password Vault Backup** - Paper backup of your password manager database
- **📝 Legal Documents** - Wills, deeds, contracts, certificates
- **🏦 Financial Records** - Tax returns, account information, insurance policies

### Disaster Recovery
- **💾 Configuration Backups** - Server configs, network settings, emergency access credentials
- **📋 Business Continuity** - Critical data for disaster recovery scenarios
- **🏚️ Off-site Storage** - Fire-resistant, water-resistant safe deposit boxes

### Long-Term Archival
- **📸 Photo Archives** - Long-term storage of irreplaceable photos (compressed)
- **📚 Code Snapshots** - Archive critical source code versions
- **⏰ Time Capsules** - Digital data intended for distant future access
- **🏛️ Institutional Archives** - Government records, historical data preservation

### Special Scenarios
- **🌐 Air-Gapped Systems** - Transfer data to/from isolated networks via paper
- **🚫 Trust-Minimized Storage** - No reliance on cloud providers or external services
- **🔬 Research Data** - Long-term storage of experimental data, analysis results

---

## Quick Start

### 1. Encode a File

```bash
python qr_code_backup.py encode myfile.txt
```

Creates `myfile.txt.qr.pdf` with QR codes.

### 2. Encode with Encryption

```bash
python qr_code_backup.py encode secrets.txt --encrypt
```

Prompts for password, encrypts before encoding.

### 3. Decode Back to Original

```bash
python qr_code_backup.py decode myfile.txt.qr.pdf -o recovered.txt
```

Scans QR codes and reconstructs the original file.

### 4. View Backup Info

```bash
python qr_code_backup.py info myfile.txt.qr.pdf
```

Shows metadata without decoding.

---

## Installation

### Requirements

- **Python 3.8+**
- **pip** (Python package manager)

### System Dependencies

QR code decoding requires system libraries:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libzbar0 poppler-utils
```

**macOS:**
```bash
brew install zbar poppler
```

**Windows:**
- Download zbar: http://zbar.sourceforge.net/
- Download poppler: https://github.com/oschwartz10612/poppler-windows/releases

### Python Dependencies

Install from requirements file:

```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install qrcode[pil] Pillow pyzbar pypdf reportlab pdf2image opencv-python numpy click cryptography argon2-cffi reedsolo
```

### Verify Installation

```bash
python qr_code_backup.py --help
```

You should see command help text.

---

## Basic Usage

### Encode Command

Convert a file to QR code PDF:

```bash
python qr_code_backup.py encode <input_file> [OPTIONS]
```

**Common Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <path>` | Output PDF file path | `<input>.qr.pdf` |
| `--encrypt` | Encrypt with password | disabled |
| `--error-correction <L\|M\|Q\|H>` | QR error correction level | M (15%) |
| `--parity-percent <0-100>` | Recovery overhead percentage | 5.0 |
| `--density <mm>` | QR code size in mm (smaller = denser) | 0.9 |
| `--title <text>` | Custom page header title | filename |

**Examples:**

```bash
# Basic encoding
python qr_code_backup.py encode document.pdf

# Encrypt sensitive data
python qr_code_backup.py encode passwords.txt --encrypt

# Maximum protection (encryption + high error correction)
python qr_code_backup.py encode keys.txt --encrypt --error-correction H

# Custom title for printed pages
python qr_code_backup.py encode data.bin --title "Production Keys 2024-01-15"

# Higher parity for critical data (10% = recover ~10% missing pages)
python qr_code_backup.py encode critical.txt --parity-percent 10.0
```

### Decode Command

Reconstruct original file from scanned QR codes:

```bash
python qr_code_backup.py decode <input_pdf> -o <output_file> [OPTIONS]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-o, --output <path>` | Output file path (required) |
| `--password <pass>` | Password for encrypted backups |
| `--recovery-mode` | Attempt recovery from damaged QR codes |
| `--force` | Overwrite existing output file |

**Examples:**

```bash
# Basic decoding
python qr_code_backup.py decode backup.pdf -o recovered.txt

# Decode encrypted backup (prompts for password)
python qr_code_backup.py decode encrypted_backup.pdf -o secrets.txt

# Provide password via command line
python qr_code_backup.py decode backup.pdf -o data.txt --password mypassword

# Attempt recovery from damaged pages
python qr_code_backup.py decode damaged.pdf -o recovered.txt --recovery-mode
```

### Info Command

View backup metadata without decoding:

```bash
python qr_code_backup.py info backup.pdf
```

**Example output:**
```
============================================================
QR CODE BACKUP METADATA
============================================================
Format Version:      Binary v1.0
Encryption:          Yes (AES-256-GCM)
Original File Size:  25,678 bytes
MD5 Hash:            3f7a8b2c1d4e5f6a7b8c9d0e1f2a3b4c
Compression:         bzip2
Total Pages:         21 (20 data + 1 parity)
Parity Overhead:     5.0%
Recovery Capacity:   1 missing page
============================================================
```

---

## Advanced Usage

### Encryption Best Practices

**Use built-in encryption for most cases:**

```bash
# Built-in: AES-256-GCM with Argon2id key derivation
python qr_code_backup.py encode secrets.txt --encrypt
```

The tool uses:
- **AES-256-GCM**: Industry-standard authenticated encryption
- **Argon2id**: Memory-hard password hashing (resistant to GPU/ASIC attacks)
- **BLAKE2b**: Fast password verification before decryption attempts
- Hardcoded secure parameters: time_cost=3, memory=64MB, parallelism=4

**External encryption (for specific cipher requirements):**

```bash
# Encrypt with GPG first
gpg -c secrets.txt  # Creates secrets.txt.gpg

# Then encode the encrypted file
python qr_code_backup.py encode secrets.txt.gpg -o backup.pdf

# To recover: decode then decrypt
python qr_code_backup.py decode backup.pdf -o recovered.gpg
gpg -d recovered.gpg > secrets.txt
```

### Error Correction Levels

Choose based on expected storage conditions:

| Level | Correction | Use Case |
|-------|-----------|----------|
| **L** | ~7% | Clean, controlled environment |
| **M** | ~15% | General use (default) |
| **Q** | ~25% | Moderate degradation expected |
| **H** | ~30% | Critical data, harsh conditions |

```bash
# Maximum error correction for long-term storage
python qr_code_backup.py encode important.txt --error-correction H
```

Higher error correction reduces capacity per QR code but increases resilience to physical damage (fading, stains, tears).

### Parity Recovery Tuning

Parity pages use Reed-Solomon erasure codes to recover missing data pages.

**Formula:** `parity_pages = ceil(parity_percent / 100 × num_data_pages)`

**Examples:**
```bash
# Default 5% - good for general use (20 data pages → 1 parity page)
python qr_code_backup.py encode file.txt

# 10% - better protection (20 data pages → 2 parity pages)
python qr_code_backup.py encode file.txt --parity-percent 10.0

# 15% - critical data (20 data pages → 3 parity pages)
python qr_code_backup.py encode file.txt --parity-percent 15.0

# Disable (not recommended for archival)
python qr_code_backup.py encode file.txt --parity-percent 0
```

**When to increase parity:**
- Long-term archival (decades): 10-15%
- Poor printing/scanning quality: 10-15%
- Critical data (zero tolerance): 15-25%
- Unreliable storage conditions: 10-20%

### Batch Processing

Encode multiple files:

```bash
# Encode all text files
for file in *.txt; do
  python qr_code_backup.py encode "$file" --encrypt
done
```

### Splitting Large Files

For files over 50 MB, split before encoding:

```bash
# Split into 10 MB chunks
split -b 10M large_file.bin chunk_

# Encode each chunk
for chunk in chunk_*; do
  python qr_code_backup.py encode "$chunk" -o "${chunk}.qr.pdf"
done

# Later, reassemble after decoding
cat chunk_* > large_file.bin
```

### Physical Backup Workflow

**Creating physical archives:**

1. **Encode with protection:**
   ```bash
   python qr_code_backup.py encode data.txt --encrypt --error-correction H -o backup.pdf
   ```

2. **Print:**
   - Use **laser printer** (more archival than inkjet)
   - Print at **actual size** (no scaling)
   - Use **acid-free paper** (archival quality)
   - Print **multiple copies** for redundancy

3. **Store:**
   - Cool, dry, dark location
   - Protective sleeves or folders
   - Fireproof/waterproof safe (optional)
   - **Multiple locations** for critical data

**Recovering from physical archives:**

1. **Scan pages:**
   - **300 DPI minimum** (higher is better)
   - Color or grayscale
   - Flat pages, good lighting
   - Save as multi-page PDF

2. **Decode:**
   ```bash
   python qr_code_backup.py decode scanned.pdf -o recovered.txt
   ```

3. **Verify:**
   - Check MD5 checksum matches
   - Compare file size
   - Test the recovered file

---

## FAQ

### How much data can I store per page?

**~1 KB per page** at default settings (after compression).

- **Text files** compress well: ~1.0-1.5 KB per page
- **Binary/random data** compresses poorly: ~0.8-1.0 KB per page
- **Already-compressed files** (ZIP, JPG, MP4): ~0.8-1.0 KB per page

**Capacity examples:**
- **Small text file** (10 KB): ~7-10 pages
- **SSH private key** (3 KB): ~3-4 pages
- **Password vault** (50 KB): ~35-50 pages
- **Bitcoin wallet** (5 KB): ~5-7 pages
- **Configuration file** (20 KB): ~15-25 pages

Default settings use:
- QR Version 15 (77×77 modules)
- Error correction M (15%)
- 2×2 grid (4 QR codes per page)
- Compression (bzip2)
- 5% parity overhead

### What happens if I lose some pages?

**The tool automatically recovers them!**

Parity pages (enabled by default at 5%) use Reed-Solomon erasure codes to reconstruct missing data.

**Example:**
```bash
# Encode with default 5% parity
python qr_code_backup.py encode data.txt
# Output: 21 pages (20 data + 1 parity)

# Later, you've lost page 7...
# Decode anyway (missing page 7)
python qr_code_backup.py decode backup.pdf -o recovered.txt

# Output:
# Missing 1 data page(s): [7]
# Found 1 parity page(s)
# Attempting parity recovery...
# Successfully recovered 1 page(s)!
# Verification: PASS
```

**Recovery capacity:**
- 5% parity: recover ~1 page per 20 data pages
- 10% parity: recover ~1 page per 10 data pages
- 15% parity: recover ~1 page per 7 data pages

**Any pages can be missing** - doesn't matter which ones. If you have enough parity pages, the tool reconstructs the missing data automatically.

### What if I scan pages out of order?

**No problem!** The tool automatically reorders them.

Each QR code contains its page number. During decode, pages are sorted automatically.

**Example:**
```bash
# You scanned pages in order: 3, 1, 4, 2 (shuffled)
python qr_code_backup.py decode shuffled.pdf -o recovered.txt

# Output:
# Reading QR codes...
# Detected QR pages: [3, 1, 4, 2]
# Pages were scanned out of order - reordering automatically...
# Verification: PASS
```

**Benefits:**
- Drop your printed pages? Just pick them up and scan
- Scan in whatever order is convenient
- No need to worry about page sequence

### What if I accidentally mix pages from different backups?

**The tool detects this immediately and stops.**

Every QR code contains the MD5 hash of its source document. If a page from a different backup is scanned, you get an immediate error:

```bash
# Accidentally mixed pages from backup_A.pdf and backup_B.pdf
python qr_code_backup.py decode mixed.pdf -o output.txt

# Output:
# ERROR: PDF page 3 contains QR code from a different document!
#
# Expected MD5: 3f7a8b2c1d4e5f6a7b8c9d0e1f2a3b4c
# Found MD5:    9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
#
# This PDF contains pages from multiple QR code backups.
```

The error shows exactly which PDF page is wrong and both MD5 hashes for comparison.

### Can I recover from damaged pages?

**Yes, with three layers of protection:**

1. **QR Error Correction** (7-30% damage per QR code)
   - Built into every QR code
   - Handles fading, stains, tears, partial obscuration
   - Use `--error-correction H` for maximum (30%)

2. **Parity Pages** (recover entire missing pages)
   - Reconstructs completely missing or unreadable pages
   - Default 5% overhead recovers ~1 in 20 pages
   - Increase with `--parity-percent` for more protection

3. **Recovery Mode** (extract partial data)
   - Try `--recovery-mode` flag during decode
   - Attempts to extract usable data from severely damaged backups
   - May produce incomplete output

**Example recovery workflow:**
```bash
# First try normal decode
python qr_code_backup.py decode damaged.pdf -o recovered.txt

# If that fails, try recovery mode
python qr_code_backup.py decode damaged.pdf -o recovered.txt --recovery-mode
```

### How secure is the encryption?

**Military-grade security using industry standards:**

- **AES-256-GCM**:
  - Symmetric encryption (256-bit key)
  - Authenticated encryption (detects tampering)
  - Quantum-resistant (as of 2024)

- **Argon2id Key Derivation**:
  - Winner of Password Hashing Competition (2015)
  - Memory-hard (requires 64MB RAM per attempt)
  - GPU/ASIC resistant (can't be accelerated by specialized hardware)
  - Time cost: 3 iterations

- **BLAKE2b Verification**:
  - Fast password pre-check
  - Wrong password detected before decryption attempt
  - Constant-time comparison (prevents timing attacks)

**Security guarantees:**
- Password never stored (only verification hash)
- Encryption happens before QR encoding (printed codes are ciphertext)
- Tampering detected automatically (GCM authentication)
- Resistant to brute-force attacks (memory-hard KDF)

**Threat model:**
- ✅ Protects against: physical theft, unauthorized access, brute force
- ✅ Secure for: encryption keys, passwords, financial data, legal documents
- ⚠️ Not protected against: quantum computers with Grover's algorithm (reduces AES-256 to ~AES-128 equivalent), rubber-hose cryptanalysis (coerced password disclosure)

### Is this suitable for very large files?

**Practical limit: ~10-50 MB**

While there's no hard limit, very large files become impractical:

| File Size | Pages (approx) | Print/Scan Time | Recommendation |
|-----------|----------------|-----------------|----------------|
| < 1 MB | < 1,000 | Minutes | ✅ Ideal |
| 1-10 MB | 1,000-10,000 | 10-30 min | ✅ Good |
| 10-50 MB | 10,000-50,000 | 30-120 min | ⚠️ Feasible but tedious |
| > 50 MB | > 50,000 | Hours | ❌ Consider splitting |

**For large files:**
```bash
# Split into manageable chunks
split -b 10M large_file.bin chunk_

# Encode each
for chunk in chunk_*; do
  python qr_code_backup.py encode "$chunk" --encrypt
done
```

### Can I use this for photos or videos?

**Yes, but only small ones.**

Multimedia files are typically already compressed (JPEG, MP4, etc.), so they won't compress further. Each page stores only ~1 KB.

**Examples:**
- **Small photo** (500 KB JPEG): ~500 pages 📄📄📄... (feasible but tedious)
- **Video clip** (10 MB MP4): ~10,000 pages (impractical)

**Better approach for photos:**
- Compress first: `tar -czf photos.tar.gz photos/`
- Split if needed: `split -b 10M photos.tar.gz chunk_`
- Encode chunks

**Recommendation:** This tool is best for **text-based data** (keys, configs, documents, code) rather than multimedia.

### How long does paper storage last?

**Depends on paper quality and storage conditions:**

| Paper Type | Storage Conditions | Lifespan |
|------------|-------------------|----------|
| **Acid-free archival** | Climate-controlled, dark | 200-500+ years |
| **Standard laser paper** | Normal indoor | 50-100 years |
| **Inkjet paper** | Normal indoor | 10-50 years |
| **Thermal paper** | Normal indoor | 5-10 years ❌ |

**Best practices for longevity:**
- Use **laser printer** (toner bonds to paper, very stable)
- Use **acid-free paper** (pH neutral, archival quality)
- Store in **cool, dry, dark** location (light and moisture degrade paper)
- Use **protective sleeves** (prevents handling damage)
- Store **multiple copies** in different locations

**Comparison to digital media:**
- Hard drives: 3-10 years typical lifespan
- SSDs: 5-10 years (data degrades without power)
- USB flash: 10-20 years
- Optical discs (CD/DVD): 10-25 years (varies widely)
- **Archival paper**: 200-500 years ✅

### Do I need to print in color?

**No, black and white is fine** (and recommended).

QR codes are binary (black/white), so color printing provides no benefit.

**Recommendations:**
- **Black and white laser**: Best choice (archival, sharp, inexpensive)
- **Grayscale laser**: Also good
- **Color laser**: Works, but wastes ink/toner
- **Inkjet**: Less archival than laser, may fade over time

### What if I forget my password?

**Your data is unrecoverable.**

This is by design—no backdoors, no password reset. The security is in your hands.

**Best practices:**
- Use a **strong but memorable** password (passphrase)
- Store password separately (password manager, safety deposit box)
- Consider **multiple encrypted copies** with different passwords (shared among trusted people)
- Include **password hints** in non-sensitive backups (stored separately)

**Example strategy for critical data:**
```bash
# Encrypt with passphrase: "correct horse battery staple"
python qr_code_backup.py encode keys.txt --encrypt

# Store password separately:
# - In password manager (digital backup)
# - In safety deposit box (paper backup)
# - Split among trusted family members (Shamir's Secret Sharing)
```

### Can I decode without this tool?

**Theoretically yes, but practically no.**

The QR codes can be scanned with any QR reader, but you'd need to:

1. Decode all QR codes to binary data
2. Parse the binary chunk format
3. Validate MD5 hashes
4. Sort chunks by page number
5. Recover missing pages (if using parity)
6. Decrypt (if encrypted) using Argon2id + AES-256-GCM
7. Decompress using bzip2

**Recommendation:**
- Store a copy of this tool with your backup (on USB stick, printed source code, etc.)
- Document your backup format clearly
- Include recovery instructions with physical backups

---

## How It Works

### Encoding Process

1. **Read** → Load input file
2. **Compress** → Apply bzip2 compression
3. **Encrypt** (optional) → AES-256-GCM with password
4. **Hash** → Calculate MD5 of compressed (possibly encrypted) data
5. **Split** → Divide into chunks (~900 bytes each)
6. **Add Metadata** → Prepend page number, MD5, encryption params to each chunk
7. **Generate Parity** → Create Reed-Solomon parity chunks
8. **Create QR Codes** → Generate QR codes with error correction
9. **Build PDF** → Arrange in 2×2 grid with headers

### Decoding Process

1. **Load PDF** → Convert pages to images
2. **Scan** → Detect and decode all QR codes
3. **Validate** → Check MD5 for mixed documents
4. **Sort** → Order chunks by page number
5. **Recover** (if needed) → Use parity to reconstruct missing pages
6. **Verify** → Check MD5 hash
7. **Decrypt** (if encrypted) → Verify password, decrypt data
8. **Decompress** → Uncompress using bzip2
9. **Write** → Save output file

### Data Format

Each QR code contains binary data with metadata:

**Page 1 (unencrypted):**
```
[Enc:1] [MD5:16] [Page#:2] [Parity:1] [Size:4] [Data:~900]
 0x00    hash     page#     0x00      bytes    chunk
```

**Page 1 (encrypted):**
```
[Enc:1] [MD5:16] [Page#:2] [Parity:1] [Size:4] [Salt:16] [Time:4]
 0x01    hash     page#     0x00      bytes    random    argon2

[Memory:4] [Parallel:4] [Verify:32] [Nonce:12] [Ciphertext:~900]
 argon2     argon2       BLAKE2b     AES-GCM   encrypted
```

**Page 2+ (encrypted/unencrypted):**
```
[Enc:1] [MD5:16] [Page#:2] [Parity:1] [Data:~900]
 0/1     hash     page#     0x00      chunk/ciphertext
```

**Parity Page:**
```
[Enc:1] [MD5:16] [Page#:2] [Parity:1] [Idx:2] [Total:2] [DataPages:2] [ParityData:~900]
 0/1     hash     page#     0x01      parity#  total     num_data     RS_parity
```

All integers are big-endian.

---

## Troubleshooting

### Encoding Issues

**"QR version too small for metadata overhead"**
- Metadata (encryption, page numbers) doesn't fit
- Solution: This shouldn't happen with current defaults; report as bug

**"File is huge after encoding"**
- Already-compressed files (ZIP, JPG, MP4) won't compress further
- Solution: This is expected; consider splitting large files

**"PDF generation is slow"**
- Normal for large files (hundreds of pages)
- Solution: Be patient, or split file into smaller chunks

### Decoding Issues

**"No QR codes found"**
- Scan quality too low, contrast too poor, or pages upside down
- Solution: Rescan at 300+ DPI, ensure good lighting, check orientation

**"Missing X pages"**
- Pages not included in scan
- Solution: Rescan missing pages, or rely on parity recovery if available

**"Cannot recover: X pages missing but only Y parity pages available"**
- Too many pages missing for available parity
- Solution: Rescan to reduce missing pages, or use `--recovery-mode`

**"Incorrect password"**
- Wrong password for encrypted backup
- Solution: Try again, check password manager, check Caps Lock

**"Mixed document detected"**
- Pages from different backups accidentally scanned together
- Solution: Separate pages by backup, rescan correct set

### System Issues

**"pyzbar not found" or "zbar shared library not found"**
```bash
# Ubuntu/Debian
sudo apt-get install libzbar0

# macOS
brew install zbar
```

**"pdf2image: Unable to convert PDF"**
```bash
# Ubuntu/Debian
sudo apt-get install poppler-utils

# macOS
brew install poppler
```

---

## Testing

Run the full test suite:

```bash
pytest tests/ -v
```

Run with coverage:

```bash
pytest --cov=qr_code_backup tests/
```

**Test coverage:**
- ✅ 45 tests passing
- Encryption (16 tests)
- Parity recovery (19 tests)
- Order independence (3 tests)
- Mixed document detection (3 tests)
- Combined features (4 tests)

### Manual Testing

Quick encode-decode cycle:

```bash
# Create test file
echo "Hello, QR Code Backup!" > test.txt

# Encode
python qr_code_backup.py encode test.txt -o test_backup.pdf

# View info
python qr_code_backup.py info test_backup.pdf

# Decode
python qr_code_backup.py decode test_backup.pdf -o recovered.txt

# Verify
diff test.txt recovered.txt
```

If `diff` produces no output, the files are identical ✅

---

## Performance

Typical performance on modern hardware (Intel i5/i7 equivalent):

- **Encoding:** ~50-100 QR codes/second
- **Decoding:** ~10-30 QR codes/second (depends on scan quality)
- **Memory usage:** ~100-500 MB

**Example timings:**
- **Small file** (10 KB, ~10 pages): < 5 seconds encode, < 10 seconds decode
- **Medium file** (100 KB, ~100 pages): ~10 seconds encode, ~30 seconds decode
- **Large file** (1 MB, ~1000 pages): ~100 seconds encode, ~300 seconds decode

---

## Limitations

- **Not for very large files** - Practical limit ~10-50 MB (becomes tedious)
- **Requires good scan quality** - 300+ DPI for reliable decoding
- **Time-consuming for large files** - Encoding/decoding 1000+ pages takes minutes
- **Paper can still degrade** - Even archival paper fails eventually with abuse
- **Compression limited** - Already-compressed files (ZIP, JPG) won't shrink further

---

## Best Practices

1. **✅ Always use parity** - Default 5% is good; increase for critical data
2. **✅ Test recovery immediately** - Decode and verify right after encoding
3. **✅ Create multiple copies** - Store in different physical locations
4. **✅ Use high error correction** - `--error-correction H` for archival
5. **✅ Document your process** - Include recovery instructions with backups
6. **✅ Store password separately** - Encrypted backup + password in same place = useless
7. **✅ Use archival materials** - Acid-free paper, laser printer
8. **✅ Regular testing** - Periodically test your backups (scan and decode)
9. **✅ Include the tool** - Store a copy of this tool with your backups
10. **✅ Verify checksums** - Always check MD5 matches during decode

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`pytest tests/ -v`)
5. Follow existing code style
6. Submit a pull request

**Areas for contribution:**
- Additional compression algorithms
- GUI frontend
- Mobile app for scanning
- Additional output formats (SVG, PNG sheets)
- Internationalization
- Performance optimizations

---

## License

**MIT License**

Copyright (c) 2024 QR Code Backup

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Acknowledgments

Built with excellent open-source libraries:

- **[qrcode](https://github.com/lincolnloop/python-qrcode)** - QR code generation
- **[pyzbar](https://github.com/NaturalHistoryMuseum/pyzbar)** - QR code decoding
- **[reportlab](https://www.reportlab.com/)** - PDF generation
- **[cryptography](https://cryptography.io/)** - AES-256-GCM encryption
- **[argon2-cffi](https://github.com/hynek/argon2-cffi)** - Argon2id key derivation
- **[reedsolo](https://github.com/tomerfiliba/reedsolomon)** - Reed-Solomon error correction
- **[pdf2image](https://github.com/Belval/pdf2image)** - PDF to image conversion

Inspired by the need for truly offline, long-term data archival independent of digital infrastructure.

---

## Version History

### v2.0.0 - Current (Phase 2)
- ✨ Parity pages for recovery (Reed-Solomon erasure codes, always-on at 5% default)
- 🔐 Password-based encryption (AES-256-GCM with Argon2id key derivation)
- 🔀 Order-independent decoding (scan pages in any order)
- 🚨 Mixed document detection (prevent accidental page mixing)
- 🗜️ Binary chunk format (replaces JSON for efficiency)
- ✅ Simplified CLI (6 essential options with opinionated defaults)
- 🧪 Comprehensive test suite (45 tests covering all features)

### v1.0.0 - Initial Release (Phase 1)
- 📄 Basic encode/decode functionality
- 🛡️ QR error correction (L/M/Q/H levels)
- 🗜️ Compression support (bzip2)
- 📋 Recovery mode for damaged backups
- ✅ Checksum verification (MD5)

---

## Support & Resources

- **📖 Documentation:** This README + `CLAUDE.md` (implementation details)
- **🐛 Bug Reports:** Open an issue on GitHub
- **💡 Feature Requests:** Open an issue with `[Feature Request]` tag
- **❓ Questions:** Check FAQ above, then open a discussion

---

**Star ⭐ this repo if you find it useful!**

*Because sometimes the best backup is the one you can hold in your hands.* 📄🔐
