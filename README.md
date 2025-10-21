# QR Code Backup

A Python command-line tool for archiving digital data as QR codes printed on paper for long-term offline storage. Perfect for backing up critical data, cryptographic keys, documents, or any file that needs to survive digital storage failures.

## Features

- **Encode any file** into multi-page PDF documents containing QR codes
- **Decode scanned PDFs** back into the original file
- **🆕 Parity pages for recovery** - Always-on Reed-Solomon erasure codes (5% default, percentage-based)
- **Password-based encryption** - AES-256-GCM with Argon2id key derivation
- **Built-in error correction** (7% to 30%) to handle paper degradation
- **Automatic compression** (bzip2) to maximize storage efficiency
- **Checksum verification** ensures data integrity with MD5 validation
- **Configurable density** - automatic QR version calculation for 2×2 grid layout
- **Professional output** with headers showing page numbers and metadata
- **Recovery mode** to extract partial data from damaged archives
- **Order-independent decoding** - scan pages in any order, automatic reordering
- **Mixed document detection** - immediate error if pages from different backups are mixed

## Use Cases

- Critical document archival (legal documents, certificates, keys)
- Offline backup of encryption keys and passwords
- Long-term photo archival
- Code repository snapshots
- Configuration backups for disaster recovery
- Digital time capsules

## Installation

### Requirements

- Python 3.8 or higher
- pip (Python package manager)

### System Dependencies

The QR code decoding requires `libzbar0`:

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install libzbar0 poppler-utils
```

**macOS:**
```bash
brew install zbar poppler
```

**Windows:**
- Download zbar from http://zbar.sourceforge.net/
- Download poppler from https://github.com/oschwartz10612/poppler-windows/releases

### Python Dependencies

Install all Python dependencies:

```bash
pip install -r requirements.txt
```

Or install them individually:
```bash
pip install qrcode[pil] Pillow pyzbar pypdf reportlab pdf2image opencv-python numpy click cryptography argon2-cffi pytest pytest-cov
```

### Verify Installation

Test that the tool works:

```bash
python qr_code_backup.py --help
```

You should see the help text with available commands.

## Quick Start

### Encode a File

Encode a text file into a QR code backup PDF:

```bash
python qr_code_backup.py encode mydata.txt -o backup.pdf
```

This creates `backup.pdf` with QR codes containing your data.

### Encode with Encryption

Protect sensitive data with password-based encryption:

```bash
python qr_code_backup.py encode secrets.txt -o backup.pdf --encrypt
```

You'll be prompted to enter a password. The data is encrypted with AES-256-GCM before encoding.

### Decode a File

Decode a scanned PDF back into the original file:

```bash
python qr_code_backup.py decode backup.pdf -o recovered.txt
```

This extracts the data and saves it as `recovered.txt`. If the PDF is encrypted, you'll be prompted for the password.

### View Metadata

Display information about an encoded PDF:

```bash
python qr_code_backup.py info backup.pdf
```

## Usage Guide

### Encode Command

```bash
python qr_code_backup.py encode <input_file> [OPTIONS]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <path>` | Output PDF file path | `<input_file>.qr.pdf` |
| `--encrypt` | Enable encryption (prompts for password) | disabled |
| `--argon2-time <n>` | Argon2 time cost parameter | 3 |
| `--argon2-memory <kb>` | Argon2 memory cost in KiB | 65536 (64MB) |
| `--argon2-parallelism <n>` | Argon2 parallelism parameter | 4 |
| `--parity-percent <n>` | Parity percentage (0-100). Default 5.0 = 5% overhead. Set to 0 to disable. | 5.0 (always enabled) |
| `--error-correction <level>` | Error correction: L(7%), M(15%), Q(25%), H(30%) | M (15%) |
| `--module-size <mm>` | QR module size in millimeters | 0.9 |
| `--page-width <mm>` | Page width in millimeters | 215.9 (Letter) |
| `--page-height <mm>` | Page height in millimeters | 279.4 (Letter) |
| `--margin <mm>` | Page margin in millimeters | 20 |
| `--spacing <mm>` | Spacing between QR codes | 5 |
| `--title <text>` | Title for page headers | filename |
| `--no-header` | Disable header text on pages | false |

**Examples:**

```bash
# Basic encoding
python qr_code_backup.py encode document.pdf

# Encrypt sensitive data
python qr_code_backup.py encode passwords.txt --encrypt

# Maximum error correction for long-term storage
python qr_code_backup.py encode important.txt --error-correction H

# Encrypted with custom Argon2 parameters (slower but more secure)
python qr_code_backup.py encode keys.txt --encrypt --argon2-time 5 --argon2-memory 131072

# Custom title
python qr_code_backup.py encode data.txt --title "Backup 2024-01-15"

# Parity is enabled by default (5% overhead, ~1 page per 20 data pages)
python qr_code_backup.py encode important.txt

# Custom parity percentage (10% = more protection, can recover ~1 page per 10 data pages)
python qr_code_backup.py encode critical.txt --parity-percent 10.0

# Disable parity (not recommended for important data)
python qr_code_backup.py encode data.txt --parity-percent 0

# Combine encryption and parity for maximum protection
python qr_code_backup.py encode secrets.txt --encrypt --error-correction H
```

### Decode Command

```bash
python qr_code_backup.py decode <input_pdf> [OPTIONS]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <path>` | Output file path (required) | - |
| `--password <pass>` | Decryption password (prompts if encrypted) | prompt |
| `--verify` | Verify checksums (enabled by default) | true |
| `--recovery-mode` | Attempt recovery from damaged QR codes | false |
| `--force` | Overwrite existing output file | false |

**Examples:**

```bash
# Basic decoding
python qr_code_backup.py decode backup.pdf -o recovered.txt

# Decode encrypted backup (will prompt for password)
python qr_code_backup.py decode encrypted.pdf -o secrets.txt

# Decode with password on command line
python qr_code_backup.py decode encrypted.pdf -o secrets.txt --password mypass

# Attempt recovery from damaged backup
python qr_code_backup.py decode damaged.pdf -o recovered.txt --recovery-mode

# Overwrite existing file
python qr_code_backup.py decode backup.pdf -o data.txt --force
```

### Info Command

Display metadata without decoding:

```bash
python qr_code_backup.py info backup.pdf
```

Example output:
```
============================================================
QR CODE BACKUP METADATA
============================================================
Format Version:      Binary v1.0
Encryption:          Yes (AES-256-GCM)
Argon2 Parameters:   time=3, memory=65536KiB, parallelism=4
Original File Size:  25,678 bytes
MD5 Hash:            3f7a8b2c1d4e5f6a7b8c9d0e1f2a3b4c
Page Number:         1
Compression:         bzip2
QR Codes per Page:   ~4
Total QR Codes:      12
PDF Pages:           3
============================================================
```

## How It Works

### Encoding Process

1. **Read file** - Load the input file into memory
2. **Compress** - Apply bzip2 compression to reduce size
3. **Encrypt (optional)** - Encrypt compressed data with AES-256-GCM if `--encrypt` is used
4. **Calculate MD5** - Generate MD5 hash of (possibly encrypted) compressed data
5. **Split into chunks** - Divide data into chunks that fit in QR codes
6. **Create metadata** - Add page numbers, MD5 hash, encryption metadata (if encrypted) to each chunk
7. **Generate QR codes** - Create QR code images with error correction
8. **Build PDF** - Arrange QR codes in a grid with headers on each page

### Decoding Process

1. **Load PDF** - Convert PDF pages to images
2. **Scan QR codes** - Detect and decode all QR codes using pyzbar
3. **Parse metadata** - Extract binary data from each QR code
4. **Validate MD5** - Check for mixed documents using MD5 hash
5. **Sort chunks** - Order chunks by page number (order-independent)
6. **Reassemble** - Concatenate chunk data in correct order
7. **Verify MD5** - Check MD5 hash of reassembled data
8. **Decrypt (if encrypted)** - Decrypt using provided password
9. **Decompress** - Uncompress data using bzip2
10. **Write output** - Save recovered file

### Data Format

Each QR code contains binary data with the following structure:

**Unencrypted data page (page 1):**
```
[0x00] [MD5:16] [Page#:2] [Parity:1=0x00] [FileSize:4] [Data:variable]
```

**Unencrypted data page (page 2+):**
```
[0x00] [MD5:16] [Page#:2] [Parity:1=0x00] [Data:variable]
```

**Encrypted data page (page 1):**
```
[0x01] [MD5:16] [Page#:2] [Parity:1=0x00] [FileSize:4] [Salt:16] [Time:4] [Memory:4]
[Parallelism:4] [VerifyHash:32] [Nonce:12] [EncryptedData:variable]
```

**Encrypted data page (page 2+):**
```
[0x01] [MD5:16] [Page#:2] [Parity:1=0x00] [EncryptedData:variable]
```

**Parity page:**
```
[Enc:1] [MD5:16] [Page#:2] [Parity:1=0x01] [ParityIdx:2] [TotalParity:2] [TotalData:2] [ParityData:variable]
```

All multi-byte integers are big-endian. MD5 is calculated on the (possibly encrypted) compressed data. Parity pages use the same MD5 as data pages for document validation.

## New Features (Phase 2)

### Password-Based Encryption

Protect sensitive data with military-grade encryption before encoding to QR codes.

**Security Features:**
- **AES-256-GCM** authenticated encryption (industry standard, quantum-resistant symmetric cipher)
- **Argon2id** key derivation (memory-hard, resistant to GPU/ASIC attacks)
- **BLAKE2b** password verification (fast pre-check before decryption attempt)
- **Constant-time comparison** prevents timing attacks

**Example:**
```bash
# Encode with encryption
python qr_code_backup.py encode passwords.txt -o backup.pdf --encrypt
Enter encryption password: ********
Repeat for confirmation: ********

# Output:
# Encryption: AES-256-GCM with Argon2id (time=3, memory=65536KiB, parallelism=4)
# Encoding: passwords.txt
# Encryption: Enabled (AES-256-GCM)
# ...

# Decode encrypted backup
python qr_code_backup.py decode backup.pdf -o recovered.txt

# Output:
# Document is encrypted (AES-256-GCM)
# Enter decryption password: ********
# Decrypting...
# Decryption successful
# Decryption: SUCCESS
# Verification: PASS
```

**Benefits:**
- Encryption happens before QR encoding - printed QR codes contain ciphertext
- Password never stored - only a verification hash (using BLAKE2b)
- Wrong password detected immediately - no wasted time on decryption
- Authenticated encryption (GCM) - tampering is detected automatically
- Memory-hard KDF - protects against brute-force attacks
- Tunable Argon2 parameters for security/performance trade-off

**Argon2 Tuning:**
```bash
# Faster (less secure, for testing)
python qr_code_backup.py encode test.txt --encrypt --argon2-time 2 --argon2-memory 32768

# Slower (more secure, for critical data)
python qr_code_backup.py encode secrets.txt --encrypt --argon2-time 5 --argon2-memory 131072
```

### Order-Independent Decoding

Pages can now be decoded in any order! If you accidentally drop your printed pages or scan them out of order, the tool automatically reorders them correctly.

**Example:**
```bash
# Even if pages are scanned in order: 3, 1, 4, 2...
python qr_code_backup.py decode shuffled_backup.pdf -o recovered.txt

# Output:
# Reading QR codes...
# Document MD5: 3f7a8b2c1d4e5f6a7b8c9d0e1f2a3b4c
# Scanning pages: [####################################] 100%
# Successfully decoded 12 QR codes from 4 PDF pages
#
# Analyzing decoded pages...
# Detected QR pages: [1, 2, 3, 4]
# Pages were scanned out of order - reordering automatically...
#
# Recovered: recovered.txt (5,120 bytes)
# Verification: PASS (MD5: 3f7a8b2c1d4e5f6a7b8c9d0e1f2a3b4c)
```

**Benefits:**
- Drop pages by accident? No problem!
- Scan in whatever order is convenient
- System automatically sorts by embedded page numbers
- Transparent feedback shows when reordering happened

### Mixed Document Detection

The tool now immediately detects if you accidentally scan pages from different backups together.

**Example:**
```bash
# Accidentally scanned pages from passwords.pdf + keys.pdf together
python qr_code_backup.py decode mixed_pages.pdf -o output.txt

# Output:
# Reading QR codes...
# Document MD5: 3f7a8b2c1d4e5f6a7b8c9d0e1f2a3b4c
# Scanning pages: [####################                ] 50%
#
# ============================================================
# ERROR: PDF page 3 contains QR code from a different document!
#
# Expected MD5 (from QR page 1): 3f7a8b2c1d4e5f6a7b8c9d0e1f2a3b4c
# Found MD5 (QR page 1):       9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
#
# This PDF contains pages from multiple QR code backups.
# Please ensure all PDF pages are from the same backup before decoding.
# ============================================================
```

**Benefits:**
- Fails fast - stops scanning as soon as wrong page is detected
- Clear error shows exactly which PDF page is wrong
- Shows both MD5 hashes for comparison
- Prevents wasting time scanning wrong pages

### Parity Pages for Recovery

Recover from missing or damaged pages using Reed-Solomon erasure codes. **Parity is always enabled by default (5% overhead)** - you can reconstruct missing data pages automatically, perfect for long-term archival where degradation is expected.

**How It Works:**
- **Reed-Solomon erasure codes** compute parity data across all data pages
- **Vertical parity** - computed byte-by-byte across chunks at each position
- **Percentage-based** - parity pages = ceil(parity_percent × data_pages). e.g., 5% of 20 pages = 1 parity page
- **Automatic recovery** - missing pages are detected and reconstructed during decode
- **Always on by default** - 5% overhead balances protection vs space (can be disabled with --parity-percent 0)

**Example:**
```bash
# Encode with default 5% parity (always enabled)
python qr_code_backup.py encode document.pdf -o backup.pdf

# Output:
# Parity: 5.0% overhead
# Generating 1 parity page(s)...
# Total pages: 21 (20 data + 1 parity)

# View parity info
python qr_code_backup.py info backup.pdf

# Output:
# Parity Pages:        1 (can recover 1 missing page)
# Data Pages:          20
# Parity Overhead:     5.0%

# Decode with a missing page (parity automatically recovers it)
python qr_code_backup.py decode backup_damaged.pdf -o recovered.pdf

# Output:
# Found 1 parity page(s)
# Missing 1 data page(s): [7]
# Attempting parity recovery...
# Successfully recovered 1 page(s)!
# Verification: PASS
```

**Custom Parity Percentage:**
```bash
# 10% parity = more protection (can recover ~10% of pages)
python qr_code_backup.py encode critical.txt --parity-percent 10.0 -o backup.pdf

# For 20 data pages: ceil(10% × 20) = 2 parity pages
# Can recover up to 2 missing pages

# Disable parity (not recommended for important data)
python qr_code_backup.py encode temp.txt --parity-percent 0 -o backup.pdf
```

**Combined with Encryption:**
```bash
# Maximum protection: encryption + default parity + high error correction
python qr_code_backup.py encode secrets.txt --encrypt --error-correction H -o backup.pdf

# Benefits:
# - Encryption protects confidentiality
# - Parity (5% default) recovers missing pages
# - QR error correction (30%) handles physical damage within each QR code
# - Triple protection for critical data!
```

**Benefits:**
- **Automatic recovery** - no manual intervention needed
- **Always on by default** - no need to remember to enable it
- **Any pages can be missing** - order doesn't matter, any combination of N pages
- **Works with encryption** - parity computed on ciphertext (doesn't leak plaintext)
- **Tunable overhead** - balance protection vs additional pages (0-100%)
- **Labeled in PDF** - parity pages clearly marked "PARITY 1/3" etc.

**When to Increase Parity:**
- **Long-term archival** - expect more degradation over decades (10-15%)
- **Unreliable scanning** - many pages may be damaged (10-20%)
- **Critical data** - can't afford to lose even multiple pages (15-25%)
- **Printing quality concerns** - some copies may have missing/unreadable pages (10-15%)

**Technical Details:**
- Uses `reedsolo` library for Reed-Solomon error correction
- Chunks padded to uniform size before parity generation
- Parity count = ceil(parity_percent / 100 × num_data_pages)
- Parity pages contain metadata: parity index, total parity, total data pages
- Recovery happens during reassemble, before decompression/decryption
- Parity works at chunk level (complements QR-level error correction)

## Data Capacity

Approximate storage capacity at default settings (QR version 15, error correction M, 3x3 grid):

| Document | Storage |
|----------|---------|
| 1 page (9 QR codes) | ~10 KB |
| 10 pages | ~100 KB |
| 100 pages | ~1 MB |
| 1000 pages | ~10 MB |

**Tips for larger files:**
- Use `--qr-version 20` or higher for more data per QR code
- Increase grid density: `--qrs-per-page 4x4` or `5x5`
- Ensure compression is enabled for text files
- Lower error correction (`--error-correction L`) if pristine storage

## Error Correction

QR codes include built-in Reed-Solomon error correction:

| Level | Correction | When to Use |
|-------|-----------|-------------|
| **L** | ~7% | Clean, controlled storage |
| **M** | ~15% | General use (default) |
| **Q** | ~25% | Moderate degradation expected |
| **H** | ~30% | Maximum protection for critical data |

Higher levels can recover from physical damage (stains, fading, tears) but reduce data capacity per QR code.

## Physical Backup Workflow

### Creating Physical Backups

1. **Encode your file:**
   ```bash
   python qr_code_backup.py encode secrets.txt --error-correction H -o backup.pdf
   ```

2. **Print the PDF:**
   - Use a laser printer (more archival than inkjet)
   - Print at actual size (not scaled)
   - Use high-quality paper (acid-free for longest life)
   - Print multiple copies for redundancy

3. **Store safely:**
   - Keep in cool, dry, dark place
   - Use protective sleeves or folders
   - Consider fireproof/waterproof safe
   - Store copies in multiple locations

### Recovering from Physical Backups

1. **Scan the pages:**
   - Use 300 DPI or higher
   - Scan in color or grayscale
   - Ensure pages are flat and well-lit
   - Save as multi-page PDF

2. **Decode the scan:**
   ```bash
   python qr_code_backup.py decode scanned_backup.pdf -o recovered.txt
   ```

3. **Verify integrity:**
   - Check that checksums match
   - Compare file size with original
   - Test the recovered file

## Troubleshooting

### Encoding Issues

**"QR version too small for metadata overhead"**
- Increase `--qr-version` (try 10, 15, or 20)

**PDF generation is slow**
- Normal for large files (hundreds of pages)
- Consider splitting large files

**File size is huge**
- Disable compression: `--compression none` for already-compressed files
- Check if file is already a compressed format (zip, jpg, mp4)

### Decoding Issues

**"No QR codes found"**
- Ensure scan quality is good (300+ DPI)
- Try improving contrast/brightness before scanning
- Check that pages are not upside down

**"Missing X pages"**
- Rescan missing pages
- If pages are damaged, use `--recovery-mode`

**"Chunk checksum failures"**
- QR code is damaged beyond error correction
- Rescan the problematic pages
- Try `--recovery-mode` to extract partial data

**"File checksum mismatch"**
- Data corruption during reassembly
- Check individual chunk checksums
- May need better quality scans

### System Dependencies

**"pyzbar not found" or "Unable to find zbar shared library"**

Linux:
```bash
sudo apt-get install libzbar0
```

macOS:
```bash
brew install zbar
```

**"pdf2image: Unable to convert PDF"**

Install poppler:

Linux:
```bash
sudo apt-get install poppler-utils
```

macOS:
```bash
brew install poppler
```

## Testing

Run the test suite:

```bash
pytest tests/ -v
```

Run with coverage:

```bash
pytest --cov=qr_code_backup tests/
```

### Manual Testing

Test the full encode-decode cycle:

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

If `diff` shows no output, the files are identical!

## Performance

Typical performance on modern hardware:

- **Encoding:** ~50-100 QR codes/second
- **Decoding:** ~10-30 QR codes/second (depends on scan quality)
- **Memory:** ~100-500 MB for typical files

A 100-page document (~900 QR codes):
- Encoding: ~10-20 seconds
- Decoding: ~30-90 seconds

## Limitations

- **Not suitable for very large files** - Practical limit around 10-50 MB
- **Requires good scan quality** - Low-quality scans may not decode
- **Time-consuming for large files** - Consider splitting multi-GB files
- **Paper degradation** - Even with error correction, extreme damage can cause data loss

## Best Practices

1. **Always verify checksums** - Don't skip verification during decode
2. **Test recovery immediately** - Decode and verify soon after creating backup
3. **Create multiple copies** - Redundancy protects against loss
4. **Store checksums separately** - Keep the SHA-256 hash in a different location
5. **Use high error correction** - For critical data, use `--error-correction H`
6. **Archive-quality materials** - Use acid-free paper and laser printer
7. **Regular testing** - Periodically scan and decode to verify backup integrity
8. **Document the process** - Include instructions for recovery with the backup

## Advanced Usage

### Encryption Best Practices

**Built-in encryption is recommended for most use cases:**

```bash
# Use built-in encryption (recommended)
python qr_code_backup.py encode secrets.txt -o backup.pdf --encrypt

# For maximum security, increase Argon2 parameters
python qr_code_backup.py encode critical_data.txt -o backup.pdf --encrypt \
  --argon2-time 5 --argon2-memory 131072 --argon2-parallelism 8
```

**External encryption (if you need specific cipher suites):**

```bash
# Encrypt with GPG first, then encode
gpg -c secrets.txt  # Creates secrets.txt.gpg
python qr_code_backup.py encode secrets.txt.gpg -o backup.pdf

# To recover: decode then decrypt
python qr_code_backup.py decode backup.pdf -o recovered.gpg
gpg -d recovered.gpg > secrets.txt
```

### Batch Processing

Encode multiple files:

```bash
for file in *.txt; do
  python qr_code_backup.py encode "$file" -o "${file}.qr.pdf"
done
```

### Splitting Large Files

For files over 50 MB, consider splitting:

```bash
# Split file into 10 MB chunks
split -b 10M largefile.bin chunk_

# Encode each chunk
for chunk in chunk_*; do
  python qr_code_backup.py encode "$chunk" -o "${chunk}.qr.pdf"
done
```

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Acknowledgments

- Uses `qrcode` library for QR code generation
- Uses `pyzbar` for QR code decoding
- Uses `reportlab` for PDF generation
- Inspired by the need for durable, offline data archival

## Support

For issues, questions, or suggestions:

- Open an issue on GitHub
- Check the troubleshooting section above
- Review the specification document: QR_CODE_BACKUP.md

## Version History

### 2.0.0 (Current - Phase 2)
- Parity pages for recovery (always-on, percentage-based, default 5% overhead)
- Password-based encryption (AES-256-GCM with Argon2id)
- Order-independent decoding (scan pages in any order)
- Mixed document detection (prevents accidental page mixing)
- Binary chunk format (replaces JSON for efficiency)
- MD5-based document validation
- Comprehensive test suite (45 tests covering encryption, parity, and integration)

### 1.0.0 (Phase 1)
- Initial release
- Encode and decode functionality
- Support for all error correction levels
- Compression support (bzip2)
- Recovery mode for damaged backups
- Comprehensive testing suite
