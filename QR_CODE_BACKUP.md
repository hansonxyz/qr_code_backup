# QR Code Backup - Specification Document

## Overview

`qr_code_backup` is a Python command-line tool for archiving digital data as QR codes printed on paper for long-term offline storage. The tool encodes data files into multi-page PDF documents containing QR codes with built-in error correction, and can decode scanned PDF documents back into the original data.

## Purpose

To provide a reliable method for long-term offline data archival that:
- Survives digital storage failures
- Remains accessible without specialized hardware
- Includes error correction for physical degradation
- Supports files of arbitrary size through multi-page spanning
- Can be retrieved using standard scanning equipment

## Features

### Core Functionality

1. **Encode Mode**: Convert any file into a multi-page PDF of QR codes
2. **Decode Mode**: Reconstruct files from scanned PDF pages
3. **Self-contained metadata**: Each QR code contains its page number for reassembly
4. **Configurable density**: Adjustable QR code size and data capacity
5. **Error correction**: Built-in Reed-Solomon error correction (default 10%)
6. **Human-readable headers**: Each page includes printed metadata

### Command-Line Interface

#### Encode Command

```bash
qr_code_backup encode <input_file> -o <output.pdf> [options]
```

**Required Arguments:**
- `input_file`: Path to the file to encode

**Options:**
- `-o, --output <path>`: Output PDF file path (default: `<input_file>.qr.pdf`)
- `--error-correction <level>`: Error correction level - L (7%), M (15%), Q (25%), H (30%) (default: M)
- `--qr-version <1-40>`: QR code version controlling size/capacity (default: auto)
- `--dpi <value>`: Output resolution in DPI (default: 300)
- `--qr-size <mm>`: Physical size of each QR code in millimeters (default: 60mm)
- `--qrs-per-page <rows>x<cols>`: Grid layout (default: 3x3 = 9 per page)
- `--title <text>`: Title to print on each page header (default: filename)
- `--page-size <size>`: Paper size - A4, Letter, Legal (default: A4)
- `--no-header`: Disable header text on pages
- `--compression <type>`: Pre-compression - none, gzip, bzip2 (default: gzip)

#### Decode Command

```bash
qr_code_backup decode <input.pdf> -o <output_file> [options]
```

**Required Arguments:**
- `input_file`: Path to scanned PDF file

**Options:**
- `-o, --output <path>`: Output file path (default: extracted from metadata or `decoded_output`)
- `--verify`: Verify integrity using checksums if available
- `--recovery-mode`: Attempt to recover from missing/damaged QR codes
- `--force`: Overwrite existing output file without prompting

#### Info Command

```bash
qr_code_backup info <file.pdf>
```

Display metadata about an encoded QR backup PDF (title, original filename, total pages, encoding parameters, etc.)

### Technical Specifications

#### Dependencies

**Required Python Libraries:**
- `qrcode` (>=7.4): QR code generation
- `Pillow` (>=10.0): Image manipulation
- `PyPDF2` or `pypdf` (>=3.0): PDF generation
- `pyzbar` (>=0.1.9): QR code decoding
- `opencv-python` (>=4.8): Image processing for decode
- `reportlab` (>=4.0): Advanced PDF generation
- `click` or `argparse`: Command-line interface

**System Dependencies:**
- Python 3.8+
- `libzbar0` (for pyzbar on Linux)
- Standard PDF reader for viewing outputs

#### Data Format

Each QR code encodes a JSON structure:

```json
{
  "format_version": "1.0",
  "file_name": "original_filename.ext",
  "file_size": 1234567,
  "total_pages": 25,
  "page_number": 1,
  "chunk_size": 2000,
  "checksum_type": "sha256",
  "file_checksum": "abc123...",
  "chunk_checksum": "def456...",
  "compression": "gzip",
  "data": "<base64_encoded_chunk>"
}
```

**Fields:**
- `format_version`: Tool version for backward compatibility
- `file_name`: Original filename for reconstruction
- `file_size`: Total size in bytes
- `total_pages`: Number of pages in complete set
- `page_number`: Current page (1-indexed)
- `chunk_size`: Bytes in this chunk (before encoding)
- `checksum_type`: Algorithm used (sha256, md5)
- `file_checksum`: Hash of complete original file
- `chunk_checksum`: Hash of this chunk for verification
- `compression`: Compression algorithm applied
- `data`: Base64-encoded (and optionally compressed) data chunk

#### PDF Layout

**Page Header (when enabled):**
```
┌─────────────────────────────────────────────┐
│ QR Code Backup Archive                      │
│ Title: [user-specified or filename]         │
│ Page X of Y                                 │
│ Decode with: qr_code_backup decode          │
└─────────────────────────────────────────────┘
```

**QR Code Grid:**
- Default: 3x3 grid (9 QR codes per page)
- Margins: 20mm on all sides
- Spacing: 10mm between QR codes
- Each QR code: 60mm × 60mm (at 300 DPI)

#### Error Correction Levels

| Level | Error Correction | Use Case |
|-------|------------------|----------|
| L     | ~7%              | Pristine storage conditions |
| M     | ~15%             | **Default** - General use |
| Q     | ~25%             | Moderate degradation expected |
| H     | ~30%             | Maximum protection |

Higher levels reduce data capacity per QR code but increase resilience.

#### Data Capacity Estimates

At default settings (QR version 10, error correction M):
- Raw capacity per QR code: ~1,250 bytes
- After JSON overhead: ~1,100 bytes of file data
- Per page (3x3): ~9,900 bytes
- 100-page document: ~990 KB
- 1000-page document: ~9.9 MB

**Optimization strategies:**
- Increase QR version (larger codes, more data)
- Increase QRs per page (smaller margins)
- Use compression for text/repetitive data
- Lower error correction for controlled environments

### Error Handling and Recovery

#### Encode Errors
- File not found or unreadable
- Insufficient disk space for output
- Invalid parameter combinations

#### Decode Errors
- Missing or damaged QR codes
- Incomplete page set
- Checksum verification failures
- Unsupported format version

#### Recovery Strategies
1. **Missing pages**: Report which pages are missing, attempt partial reconstruction
2. **Damaged QR codes**: Use error correction if damage is within tolerance
3. **Recovery mode**: Accept partial data, output what can be recovered
4. **Duplicate pages**: Use checksum to verify and accept any valid copy

### Validation and Verification

#### Encode Process
1. Calculate file checksum before splitting
2. Embed checksum in every QR code
3. Generate verification report with file hash

#### Decode Process
1. Read all QR codes from all pages
2. Verify page sequence (check for gaps)
3. Validate individual chunk checksums
4. Reassemble data chunks
5. Verify final file checksum
6. Report any discrepancies

### Output Examples

#### Successful Encode
```
Encoding: important_data.zip (2.4 MB)
Compression: gzip (reduced to 1.8 MB)
QR Configuration: Version 15, Error Correction M
Pages required: 18
Generating QR codes... [====================] 100%
Writing PDF... done
Output: important_data.zip.qr.pdf

Verification hash (SHA-256): a1b2c3d4...
Store this hash separately to verify successful recovery.
```

#### Successful Decode
```
Decoding: backup_scan.pdf
Found 18 pages
Reading QR codes... [====================] 100%
18/18 pages successfully decoded
Reassembling data... done
Decompressing... done
Verifying checksum... PASS

Recovered: important_data.zip (2.4 MB)
Verification hash: a1b2c3d4... [MATCH]
```

#### Partial Recovery
```
Decoding: damaged_backup.pdf
Found 18 pages
Reading QR codes... [====================] 100%
Warning: Page 7 - QR code 3 unreadable
Warning: Page 12 - QR code 1 damaged (recovered via error correction)
16/18 pages successfully decoded

ERROR: Cannot fully reconstruct file (missing 2 QR codes)
Use --recovery-mode to extract partial data (may be corrupted)
```

### Use Cases

1. **Critical document archival**: Legal documents, certificates, keys
2. **Code repository snapshots**: Store codebase versions offline
3. **Family photos**: Long-term archival of digital photos
4. **Cryptographic keys**: Offline backup of encryption keys
5. **Configuration backups**: System configs for disaster recovery
6. **Time capsules**: Digital data for multi-decade preservation

### Performance Considerations

#### Encoding Performance
- **CPU-bound**: QR code generation is the bottleneck
- Expected: ~50-100 QR codes/second on modern hardware
- 100-page document (~900 codes): ~10-20 seconds

#### Decoding Performance
- **I/O and CPU-bound**: PDF parsing and image recognition
- Expected: ~10-30 QR codes/second (depends on scan quality)
- 100-page document: ~30-90 seconds

#### Storage Efficiency
- Overhead: ~15-20% from JSON structure and Base64 encoding
- Compression can offset this for text/repetitive data
- Raw binary data: expect ~1.2-1.3x size increase

### Future Enhancements

1. **Progressive encoding**: Resume interrupted encoding
2. **Reed-Solomon at file level**: Additional error correction across chunks
3. **Encryption**: Built-in encryption before encoding
4. **Web interface**: Browser-based encoding/decoding
5. **Mobile app**: Decode using smartphone camera
6. **Parity pages**: Extra pages for reconstruction of missing data
7. **Color QR codes**: Increased density (experimental)
8. **Batch processing**: Multiple files in one document

### Testing Requirements

1. **Unit tests**: Individual functions (encoding, decoding, checksum)
2. **Integration tests**: Full encode-decode cycle
3. **Edge cases**: Empty files, very large files, binary vs text
4. **Error injection**: Simulate damaged QR codes, missing pages
5. **Format compatibility**: Different PDF scanners and readers
6. **Performance benchmarks**: Encoding/decoding speed tests
7. **Physical tests**: Print and scan actual documents

### Success Criteria

- Successfully encode and decode files from 1 KB to 10 MB
- Survive 30% QR code damage with error correction level H
- Successful decode from consumer-grade scanner (300 DPI)
- Processing time < 1 minute for typical 50-page document
- Clear error messages for all failure modes
- Comprehensive documentation and help text

## License and Distribution

- Recommended: Open source (MIT or Apache 2.0)
- Distribute via PyPI: `pip install qr_code_backup`
- Include example files and tutorial
