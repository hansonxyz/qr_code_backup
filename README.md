# QR Code Backup

QR Code Backup is a command-line tool for archiving digital data as QR codes printed on paper. It encodes files into multi-page PDFs containing QR codes with error correction, and can decode scanned PDFs back into the original files.

**Storage capacity: ~1.5 KB per printed page** at default settings (0.8mm density)

[See example PDF](examples/3k_example_rfc_1149.pdf)

## Features

- **High density storage** - ~1.5 KB per page (20 KB file → 13 pages)
- **Encode any file** into multi-page PDF documents containing QR codes
- **Decode scanned PDFs** back into the original file with verification
- **Password-based encryption** using AES-256-GCM with Argon2id key derivation (zero page overhead)
- **Parity pages** for automatic recovery from missing pages using Reed-Solomon erasure codes (5% overhead by default)
- **Order-independent decoding** - scan pages in any order, automatic reordering
- **Mixed document detection** - prevents accidentally mixing pages from different backups
- **Built-in error correction** (7% to 30%) to handle paper degradation and damage
- **Automatic compression** using bzip2 to maximize storage efficiency
- **Checksum verification** ensures data integrity with MD5 validation

## Use Cases

- Critical document archival (legal documents, certificates, encryption keys)
- Offline backup of passwords and cryptographic keys
- Long-term data storage independent of digital media
- Disaster recovery scenarios
- Air-gapped data transfer
- Time capsules and institutional archives

## Installation

### System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libzbar0 poppler-utils libgl1-mesa-glx libglib2.0-0
```

**macOS:**
```bash
brew install zbar poppler
```

**Windows:**
```bash
choco install zbar poppler
```

### Python Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Encode

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
| `--density <mm>` | QR module density in mm | 0.8 |
| `--title <text>` | Custom page header title | filename |

**Examples:**

```bash
# Basic encoding
python qr_code_backup.py encode document.pdf

# With encryption
python qr_code_backup.py encode passwords.txt --encrypt

# Maximum protection
python qr_code_backup.py encode keys.txt --encrypt --error-correction H

# Custom parity percentage
python qr_code_backup.py encode critical.txt --parity-percent 10.0
```

### Decode

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

# Encrypted backup
python qr_code_backup.py decode encrypted_backup.pdf -o secrets.txt

# With recovery mode
python qr_code_backup.py decode damaged.pdf -o recovered.txt --recovery-mode
```

### Info

```bash
python qr_code_backup.py info backup.pdf
```

Displays metadata without decoding.

## Technical Details

### Data Capacity

**~1.5 KB per page** at default settings (0.8mm density, Version 21 QR codes, including 5% parity overhead).

Measured benchmarks:
- 20 KB file → 13 PDF pages (51 QR codes)
- Encryption adds zero page overhead
- Parity at 5% adds ~1 page per 20 data pages

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

### Encryption

- **AES-256-GCM**: Authenticated encryption
- **Argon2id**: Memory-hard key derivation
- **BLAKE2b**: Password verification
- Parameters: time_cost=3, memory=64MB, parallelism=4

Password is never stored, only a verification hash. Tampering is detected automatically.

### Parity Recovery

Reed-Solomon erasure codes enable recovery of missing pages.

Formula: `parity_pages = ceil(parity_percent / 100 × num_data_pages)`

Any N parity pages can recover any N missing data pages.

### Error Correction

QR codes include Reed-Solomon error correction:

| Level | Correction |
|-------|-----------|
| L | ~7% |
| M | ~15% (default) |
| Q | ~25% |
| H | ~30% |

Higher levels can recover from more damage but reduce data capacity per QR code.

## Testing

```bash
pytest tests/ -v
```

All 45 tests covering encryption, parity recovery, order independence, mixed document detection, and integration.

## License

MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

- [qrcode](https://github.com/lincolnloop/python-qrcode) - QR code generation
- [pyzbar](https://github.com/NaturalHistoryMuseum/pyzbar) - QR code decoding
- [reportlab](https://www.reportlab.com/) - PDF generation
- [cryptography](https://cryptography.io/) - AES-256-GCM encryption
- [argon2-cffi](https://github.com/hynek/argon2-cffi) - Argon2id key derivation
- [reedsolo](https://github.com/tomerfiliba/reedsolomon) - Reed-Solomon error correction
