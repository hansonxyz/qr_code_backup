# QR Code Backup

A Python command-line tool for archiving digital data as QR codes printed on paper for long-term offline storage. Perfect for backing up critical data, cryptographic keys, documents, or any file that needs to survive digital storage failures.

## Features

- **Encode any file** into multi-page PDF documents containing QR codes
- **Decode scanned PDFs** back into the original file
- **Built-in error correction** (7% to 30%) to handle paper degradation
- **Automatic compression** (bzip2) to maximize storage efficiency
- **Checksum verification** ensures data integrity with MD5 validation
- **Configurable density** - automatic QR version calculation for 2×2 grid layout
- **Professional output** with headers showing page numbers and metadata
- **Recovery mode** to extract partial data from damaged archives
- **🆕 Order-independent decoding** - scan pages in any order, automatic reordering
- **🆕 Mixed document detection** - immediate error if pages from different backups are mixed

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
pip install qrcode[pil] Pillow pyzbar pypdf reportlab pdf2image opencv-python numpy click pytest pytest-cov
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

### Decode a File

Decode a scanned PDF back into the original file:

```bash
python qr_code_backup.py decode backup.pdf -o recovered.txt
```

This extracts the data and saves it as `recovered.txt`.

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
| `--error-correction <level>` | Error correction: L(7%), M(15%), Q(25%), H(30%) | M (15%) |
| `--qr-version <1-40>` | QR code version (size) | auto |
| `--dpi <value>` | Output resolution | 300 |
| `--qr-size <mm>` | Physical QR code size in millimeters | 60 |
| `--qrs-per-page <RxC>` | Grid layout (rows x cols) | 3x3 |
| `--title <text>` | Title for page headers | filename |
| `--page-size <size>` | Paper size: A4, LETTER, LEGAL | A4 |
| `--no-header` | Disable header text on pages | false |
| `--compression <type>` | Compression: none, gzip, bzip2 | gzip |

**Examples:**

```bash
# Basic encoding
python qr_code_backup.py encode document.pdf

# Maximum error correction for long-term storage
python qr_code_backup.py encode important.txt --error-correction H

# Higher density (more QR codes per page)
python qr_code_backup.py encode data.bin --qrs-per-page 4x4 --qr-size 50

# No compression for already compressed files
python qr_code_backup.py encode archive.zip --compression none

# Custom title and Letter paper size
python qr_code_backup.py encode keys.txt --title "Encryption Keys" --page-size LETTER
```

### Decode Command

```bash
python qr_code_backup.py decode <input_pdf> [OPTIONS]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <path>` | Output file path | from metadata |
| `--verify` | Verify checksums (enabled by default) | true |
| `--recovery-mode` | Attempt recovery from damaged QR codes | false |
| `--force` | Overwrite existing output file | false |

**Examples:**

```bash
# Basic decoding
python qr_code_backup.py decode backup.pdf

# Decode to specific filename
python qr_code_backup.py decode scanned_backup.pdf -o recovered_data.txt

# Attempt recovery from damaged backup
python qr_code_backup.py decode damaged.pdf --recovery-mode

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
Format Version:      1.0
Original Filename:   important_data.txt
Original File Size:  25,678 bytes
Total Pages:         3
Compression:         gzip
Checksum Type:       sha256
File Checksum:       a1b2c3d4e5f6...
QR Codes per Page:   ~9
PDF Pages:           3
============================================================
```

## How It Works

### Encoding Process

1. **Read file** - Load the input file into memory
2. **Compress** - Apply compression (gzip by default) to reduce size
3. **Calculate checksums** - Generate SHA-256 hash of original file
4. **Split into chunks** - Divide data into chunks that fit in QR codes
5. **Create metadata** - Add page numbers, checksums, filename to each chunk
6. **Generate QR codes** - Create QR code images with error correction
7. **Build PDF** - Arrange QR codes in a grid with headers on each page

### Decoding Process

1. **Load PDF** - Convert PDF pages to images (300 DPI)
2. **Scan QR codes** - Detect and decode all QR codes using pyzbar
3. **Parse metadata** - Extract JSON data from each QR code
4. **Sort and validate** - Order chunks by page number, verify checksums
5. **Reassemble** - Concatenate chunk data in correct order
6. **Decompress** - Uncompress data using stored compression method
7. **Verify** - Check final file checksum matches expected value
8. **Write output** - Save recovered file

### Data Format

Each QR code contains a JSON structure:

```json
{
  "format_version": "1.0",
  "file_name": "mydata.txt",
  "file_size": 12345,
  "total_pages": 5,
  "page_number": 1,
  "chunk_size": 1100,
  "checksum_type": "sha256",
  "file_checksum": "abc123...",
  "chunk_checksum": "def456...",
  "compression": "gzip",
  "data": "<base64_encoded_chunk>"
}
```

## New Features (Phase 2)

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

### Encrypting Before Backup

For sensitive data, encrypt before encoding:

```bash
# Encrypt with GPG
gpg -c secrets.txt  # Creates secrets.txt.gpg

# Encode encrypted file
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

### 1.0.0 (Current)
- Initial release
- Encode and decode functionality
- Support for all error correction levels
- Compression support (gzip, bzip2)
- Recovery mode for damaged backups
- Comprehensive testing suite
