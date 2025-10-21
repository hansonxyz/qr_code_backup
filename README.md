# QR Code Backup

QR Code Backup is a command-line tool for archiving digital data as QR codes printed on paper. It encodes files into multi-page PDFs containing QR codes with error correction, and can decode scanned PDFs back into the original files.

## Features

- **Encode any file** into multi-page PDF documents containing QR codes
- **Decode scanned PDFs** back into the original file with verification
- **Password-based encryption** using AES-256-GCM with Argon2id key derivation
- **Parity pages** for automatic recovery from missing pages using Reed-Solomon erasure codes (5% overhead by default)
- **Order-independent decoding** - scan pages in any order, automatic reordering
- **Mixed document detection** - prevents accidentally mixing pages from different backups
- **Built-in error correction** (7% to 30%) to handle paper degradation and damage
- **Automatic compression** using bzip2 to maximize storage efficiency
- **Checksum verification** ensures data integrity with MD5 validation
- **Configurable density** with automatic QR version calculation

All processing is done locally with no network connectivity required.

## Use Cases

- Critical document archival (legal documents, certificates, encryption keys)
- Offline backup of passwords and cryptographic keys
- Long-term data storage independent of digital media
- Disaster recovery scenarios
- Air-gapped data transfer
- Time capsules and institutional archives

## Installation

### Requirements

- Python 3.8 or higher
- System dependencies for QR decoding

### System Dependencies

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
- Download zbar from http://zbar.sourceforge.net/
- Download poppler from https://github.com/oschwartz10612/poppler-windows/releases

### Python Dependencies

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

## Quick Start

Encode a file:
```bash
python qr_code_backup.py encode myfile.txt
```

Encode with encryption:
```bash
python qr_code_backup.py encode secrets.txt --encrypt
```

Decode back to original:
```bash
python qr_code_backup.py decode myfile.txt.qr.pdf -o recovered.txt
```

View metadata:
```bash
python qr_code_backup.py info myfile.txt.qr.pdf
```

## Usage

### Encode Command

```bash
python qr_code_backup.py encode <input_file> [OPTIONS]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <path>` | Output PDF file path | `<input>.qr.pdf` |
| `--encrypt` | Encrypt with password | disabled |
| `--error-correction <L\|M\|Q\|H>` | QR error correction level | M (15%) |
| `--parity-percent <0-100>` | Recovery overhead percentage | 5.0 |
| `--density <mm>` | QR code size in mm | 0.9 |
| `--title <text>` | Custom page header title | filename |

**Examples:**

```bash
# Basic encoding
python qr_code_backup.py encode document.pdf

# Encrypt sensitive data
python qr_code_backup.py encode passwords.txt --encrypt

# Maximum protection
python qr_code_backup.py encode keys.txt --encrypt --error-correction H

# Higher parity for critical data (10% overhead)
python qr_code_backup.py encode critical.txt --parity-percent 10.0
```

### Decode Command

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

# Decode encrypted backup
python qr_code_backup.py decode encrypted_backup.pdf -o secrets.txt

# Attempt recovery from damaged pages
python qr_code_backup.py decode damaged.pdf -o recovered.txt --recovery-mode
```

### Info Command

Display metadata without decoding:

```bash
python qr_code_backup.py info backup.pdf
```

## Data Capacity

Approximately **1 KB per page** at default settings (after compression).

- Text files: ~1.0-1.5 KB per page
- Binary/random data: ~0.8-1.0 KB per page
- Already-compressed files: ~0.8-1.0 KB per page

**Examples:**
- SSH private key (3 KB): 3-4 pages
- Password vault (50 KB): 35-50 pages
- Configuration file (20 KB): 15-25 pages

Default settings use QR Version 15 (77×77 modules), error correction M (15%), 2×2 grid (4 QR codes per page), bzip2 compression, and 5% parity overhead.

## How It Works

### Encoding Process

1. Read input file
2. Compress using bzip2
3. Optionally encrypt with AES-256-GCM
4. Calculate MD5 hash of compressed data
5. Split into chunks (~900 bytes each)
6. Add metadata (page number, MD5, encryption params)
7. Generate Reed-Solomon parity chunks
8. Create QR codes with error correction
9. Build PDF with 2×2 grid layout and headers

### Decoding Process

1. Convert PDF pages to images
2. Scan and decode all QR codes
3. Validate MD5 to detect mixed documents
4. Sort chunks by page number (order-independent)
5. Recover missing pages using parity data if needed
6. Verify MD5 hash of reassembled data
7. Decrypt if encrypted
8. Decompress using bzip2
9. Write output file

### Data Format

Each QR code contains binary metadata followed by data:

**Unencrypted data page:**
```
[0x00][MD5:16 bytes][Page#:2 bytes][Parity:1 byte][FileSize:4 bytes (page 1 only)][Data:variable]
```

**Encrypted data page:**
```
[0x01][MD5:16 bytes][Page#:2 bytes][Parity:1 byte][FileSize:4 bytes][Salt:16][Time:4][Memory:4][Parallelism:4][VerifyHash:32][Nonce:12][EncryptedData:variable]
```

**Parity page:**
```
[Enc:1][MD5:16][Page#:2][Parity:1=0x01][ParityIdx:2][TotalParity:2][TotalData:2][ParityData:variable]
```

All integers are big-endian. MD5 is calculated on compressed (possibly encrypted) data.

## Encryption

Built-in encryption uses industry-standard cryptography:

- **AES-256-GCM**: Authenticated encryption (confidentiality + integrity)
- **Argon2id**: Memory-hard key derivation (resistant to GPU/ASIC attacks)
- **BLAKE2b**: Fast password verification
- Hardcoded secure parameters: time_cost=3, memory=64MB, parallelism=4

Password never stored, only verification hash. Tampering detected automatically.

## Parity Recovery

Parity pages use Reed-Solomon erasure codes to recover missing data pages.

**Formula:** `parity_pages = ceil(parity_percent / 100 × num_data_pages)`

**Examples:**
- 5% parity (default): 1 parity page per 20 data pages
- 10% parity: 1 parity page per 10 data pages
- 15% parity: 1 parity page per 7 data pages

Any N parity pages can recover any N missing data pages, regardless of which pages are missing.

## Error Correction Levels

QR codes include built-in Reed-Solomon error correction:

| Level | Correction | Use Case |
|-------|-----------|----------|
| L | ~7% | Clean, controlled storage |
| M | ~15% | General use (default) |
| Q | ~25% | Moderate degradation expected |
| H | ~30% | Maximum protection |

Higher levels can recover from physical damage (stains, fading, tears) but reduce data capacity per QR code.

## Physical Backup Workflow

**Creating backups:**

1. Encode with protection:
   ```bash
   python qr_code_backup.py encode data.txt --encrypt --error-correction H -o backup.pdf
   ```

2. Print:
   - Use laser printer (more archival than inkjet)
   - Print at actual size (no scaling)
   - Use acid-free paper (archival quality)
   - Print multiple copies for redundancy

3. Store:
   - Cool, dry, dark location
   - Protective sleeves or folders
   - Fireproof/waterproof safe (optional)
   - Multiple locations for critical data

**Recovering from backups:**

1. Scan pages at 300 DPI minimum (higher is better)
2. Save as multi-page PDF
3. Decode:
   ```bash
   python qr_code_backup.py decode scanned.pdf -o recovered.txt
   ```
4. Verify checksum matches

## FAQ

### What happens if I lose some pages?

The tool automatically recovers them using parity pages. Default 5% parity overhead can recover approximately 1 page per 20 data pages. Any pages can be missing - doesn't matter which ones.

### What if I scan pages out of order?

No problem. Each QR code contains its page number and pages are sorted automatically during decode.

### What if I accidentally mix pages from different backups?

The tool detects this immediately and stops with an error showing which page is from a different document. Every QR code contains the MD5 hash of its source document.

### Can I recover from damaged pages?

Yes, with three layers of protection:

1. **QR Error Correction** (7-30% per QR code) - handles fading, stains, tears
2. **Parity Pages** - reconstructs completely missing or unreadable pages
3. **Recovery Mode** - attempts to extract partial data from severely damaged backups

### How secure is the encryption?

Military-grade security using AES-256-GCM (quantum-resistant symmetric encryption) with Argon2id key derivation (memory-hard, GPU/ASIC resistant). Password never stored, only verification hash. Tampering detected automatically via GCM authentication.

### Is this suitable for large files?

Practical limit is approximately 10-50 MB. Very large files become impractical due to the number of pages required. For files over 50 MB, consider splitting into chunks before encoding.

### How long does paper storage last?

Depends on paper quality and storage conditions:

- Acid-free archival paper in climate-controlled storage: 200-500+ years
- Standard laser paper indoors: 50-100 years
- Inkjet paper indoors: 10-50 years

Use laser printer (toner is more stable than ink) and acid-free paper for longest lifespan.

### What if I forget my password?

Data is unrecoverable. No backdoors, no password reset. Store password separately in a password manager or safety deposit box.

## Performance

Typical performance on modern hardware:

- **Encoding:** ~50-100 QR codes/second
- **Decoding:** ~10-30 QR codes/second (depends on scan quality)
- **Memory usage:** ~100-500 MB

Example timings:
- Small file (10 KB): < 5 seconds encode, < 10 seconds decode
- Medium file (100 KB): ~10 seconds encode, ~30 seconds decode
- Large file (1 MB): ~100 seconds encode, ~300 seconds decode

## Limitations

- Not suitable for very large files (practical limit ~10-50 MB)
- Requires good scan quality (300+ DPI)
- Time-consuming for files with 1000+ pages
- Paper can degrade despite archival quality
- Already-compressed files (ZIP, JPG) won't compress further

## Testing

Run the test suite:

```bash
pytest tests/ -v
```

Run with coverage:

```bash
pytest --cov=qr_code_backup tests/
```

All 45 tests covering encryption, parity recovery, order independence, mixed document detection, and integration.

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Security

For security vulnerabilities, see [SECURITY.md](SECURITY.md) for responsible disclosure process. Do not report security issues publicly.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

Built with open-source libraries:

- [qrcode](https://github.com/lincolnloop/python-qrcode) - QR code generation
- [pyzbar](https://github.com/NaturalHistoryMuseum/pyzbar) - QR code decoding
- [reportlab](https://www.reportlab.com/) - PDF generation
- [cryptography](https://cryptography.io/) - AES-256-GCM encryption
- [argon2-cffi](https://github.com/hynek/argon2-cffi) - Argon2id key derivation
- [reedsolo](https://github.com/tomerfiliba/reedsolomon) - Reed-Solomon error correction

## Version History

### v2.0.0 (Current)
- Password-based encryption (AES-256-GCM with Argon2id)
- Parity pages for recovery (Reed-Solomon, always-on at 5% default)
- Order-independent decoding
- Mixed document detection
- Simplified CLI with opinionated defaults
- Binary chunk format v2.0

### v1.0.0
- Initial release
- Basic encode/decode functionality
- QR error correction (L/M/Q/H)
- Compression support (bzip2)
- Recovery mode for damaged backups
