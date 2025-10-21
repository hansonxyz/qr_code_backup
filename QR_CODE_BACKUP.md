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
- `--module-size <mm>`: QR module size in millimeters (default: 0.9mm)
- `--page-width <mm>`: Page width in millimeters (default: 215.9mm = US Letter)
- `--page-height <mm>`: Page height in millimeters (default: 279.4mm = US Letter)
- `--margin <mm>`: Page margin in millimeters (default: 20mm)
- `--spacing <mm>`: Spacing between QR codes in millimeters (default: 5mm)
- `--title <text>`: Title to print on each page header (default: filename)
- `--no-header`: Disable header text on pages

**Key Features:**
- **Auto-calculated QR version**: Automatically selects optimal QR version to maintain 2×2 grid layout (4 codes per page)
- **Hardcoded compression**: Always uses bzip2 compression
- **Binary metadata format**: Efficient binary format with MD5 validation

#### Decode Command

```bash
qr_code_backup decode <input.pdf> -o <output_file> [options]
```

**Required Arguments:**
- `input_file`: Path to scanned PDF file
- `-o, --output <path>`: Output file path (required in binary format v1.0)

**Options:**
- `--verify`: Verify integrity using MD5 checksums (default: enabled)
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

**Binary Metadata Format (v1.0):**

Each QR code contains binary metadata followed by data (entire chunk is base64 encoded):

**Page 1 Format:**
```
[MD5 Hash: 16 bytes][Page Number: 2 bytes uint16][File Size: 4 bytes uint32][Data: variable]
```

**Other Pages Format:**
```
[MD5 Hash: 16 bytes][Page Number: 2 bytes uint16][Data: variable]
```

**Fields:**
- **MD5 Hash** (16 bytes binary): Hash of the entire compressed file
  - Same on every page for validation
  - Detects mixed documents (different MD5 = different file)
  - Verifies data integrity after reassembly

- **Page Number** (2 bytes, big-endian uint16): 1-indexed page number
  - Range: 1 to 65,536 (2^16 limit)
  - Used for sequence validation and reassembly

- **File Size** (4 bytes, big-endian uint32, page 1 only):
  - Original uncompressed file size
  - Range: 0 to 4,294,967,296 bytes (2^32 = 4GB limit)
  - Not present on pages 2+

- **Data** (variable): Chunk of bzip2-compressed file data

**Validation Features:**
- MD5 consistency check across all pages
- Page sequence validation (1, 2, 3, ... N with no gaps)
- Duplicate page detection
- Mixed document detection
- Final MD5 verification after reassembly

**Metadata Overhead:**
- Page 1: 22 bytes (MD5 + Page# + FileSize)
- Other pages: 18 bytes (MD5 + Page#)
- Plus ~33% for base64 encoding

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
- Default: 2×2 grid (4 QR codes per page)
- Auto-calculated based on module size and page dimensions
- Margins: 20mm on all sides (configurable)
- Spacing: 5mm between QR codes (configurable)
- QR codes are horizontally centered on page
- Each QR code size depends on module size and auto-calculated version
  - Example: 0.9mm module × Version 18 = 81.9mm × 81.9mm per code

#### Error Correction Levels

| Level | Error Correction | Use Case |
|-------|------------------|----------|
| L     | ~7%              | Pristine storage conditions |
| M     | ~15%             | **Default** - General use |
| Q     | ~25%             | Moderate degradation expected |
| H     | ~30%             | Maximum protection |

Higher levels reduce data capacity per QR code but increase resilience.

#### Data Capacity Estimates

At default settings (0.9mm module size, auto-calculated version 18, error correction M):
- QR code version: 18 (auto-calculated to fit 2×2 grid)
- Chunk size: ~314 bytes per QR code
- Per page (2×2): ~1,256 bytes
- 5KB file: ~19 QR codes = 5 PDF pages
- 25KB file: ~80 QR codes = 20 PDF pages

**Recommended file sizes:**
- Small files (< 5KB): 1-5 pages
- Medium files (5-25KB): 5-20 pages
- Practical limit: ~25KB (anything larger becomes unwieldy to print/scan)

**Tuning capacity:**
- Smaller module size (0.7mm): Larger QR version → more data per code (riskier scanning)
- Larger module size (1.2mm): Smaller QR version → less data per code (safer scanning)
- System automatically adjusts QR version to maintain 2×2 grid layout

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
1. Compress file with bzip2
2. Calculate MD5 hash of compressed data
3. Check file size limit (2^32 bytes maximum)
4. Check page count limit (2^16 pages maximum)
5. Embed MD5 hash in every QR code
6. Generate verification report with MD5 hash

#### Decode Process (Binary Format v1.0)
1. Read all QR codes from all pages (returns binary chunks)
2. Parse binary metadata from each chunk
3. **MD5 Consistency Check**: Verify all chunks have identical MD5 hash
   - Detects mixed documents (accidentally scanned pages from different backups)
4. **Page Sequence Validation**: Verify pages are 1, 2, 3, ... N with no gaps
   - Detects missing pages
5. **Duplicate Detection**: Check for duplicate page numbers
6. Reassemble data chunks in correct order
7. Decompress with bzip2
8. **Final MD5 Verification**: Verify MD5 of reassembled compressed data matches page headers
9. Report any discrepancies with detailed error messages

**Error Messages:**
- `"Mixed documents detected! Pages [X, Y] have different MD5 hashes"`
- `"Missing pages in sequence: [3, 7]. All pages from 1 to N must be present"`
- `"Duplicate pages detected: [2, 5]"`
- `"Page 1 not found - cannot determine file size"`
- `"MD5 verification failed! Data corruption detected"`

### New Features (Phase 2)

#### Order-Independent Decoding

**What it does:** Pages can be scanned and decoded in any order - the system automatically reorders them correctly.

**Why it matters:**
- Accidentally dropped/shuffled printed pages? No problem!
- Scan pages in any order you like
- Pages are automatically sorted by their embedded page numbers

**How it works:**
1. Each QR code contains its page number in binary metadata
2. System reads all QR codes from all pages
3. Automatically sorts chunks by page number during reassembly
4. Shows you which pages were detected and confirms if reordering happened

**User Experience:**
```
Reading QR codes...
Document MD5: 3f7a8b2c1d4e5f6a7b8c9d0e1f2a3b4c
Scanning pages: [####################################] 100%
Successfully decoded 12 QR codes from 3 PDF pages

Analyzing decoded pages...
Detected QR pages: [1, 2, 3]
Pages were scanned out of order - reordering automatically...
```

#### Mixed Document Detection

**What it does:** Immediately detects and stops if you accidentally scan pages from different QR code backups together.

**Why it matters:**
- Prevents accidentally mixing pages from `passwords.pdf` with pages from `keys.pdf`
- Fails fast - stops scanning as soon as wrong page is detected
- Shows exactly which page is wrong with clear error message

**How it works:**
1. First QR code establishes the "reference" MD5 hash
2. Every subsequent QR code is checked against this reference
3. If a different MD5 is found → immediate error with details
4. Shows PDF page number and both MD5 hashes for comparison

**User Experience (Error Case):**
```
Reading QR codes...
Document MD5: 3f7a8b2c1d4e5f6a7b8c9d0e1f2a3b4c
Scanning pages: [####################                ] 50%

============================================================
ERROR: PDF page 3 contains QR code from a different document!

Expected MD5 (from QR page 1): 3f7a8b2c1d4e5f6a7b8c9d0e1f2a3b4c
Found MD5 (QR page 1):       9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d

This PDF contains pages from multiple QR code backups.
Please ensure all PDF pages are from the same backup before decoding.
============================================================
```

**Benefits:**
- **Faster failure**: Don't waste time scanning all wrong pages
- **Clear identification**: Shows exact PDF page number where problem was found
- **Actionable**: Remove the wrong page and try again
- **Debugging help**: Both MD5 hashes shown for comparison

### Output Examples

#### Successful Encode
```
Encoding: /workspace/tests/test_data/random_5kb.bin
Page: 215.9mm × 279.4mm (margin: 20.0mm, spacing: 5.0mm)
QR Configuration: Version 18, Error Correction M
QR Module Size: 0.9mm → Physical QR Size: 81.9mm
Grid Layout: 2 rows × 2 columns = 4 QR codes per page
Chunk size: 314 bytes per QR code
Compressing with bzip2...
  Original size: 5,120 bytes
  Compressed size: 5,617 bytes (109.7%)
QR codes required: 19
PDF pages required: 5
Generating QR codes...
Creating QR codes  [####################################]  100%
Writing PDF...

Output: random_5kb.bin.qr.pdf
Verification hash (MD5): ea4ca35ea7c1f774621e2191fad85b4c
Store this hash separately to verify successful recovery.
```

#### Successful Decode
```
Decoding: random_5kb.bin.qr.pdf
Converting PDF to images...
Found 5 pages
Reading QR codes...
Scanning pages  [####################################]  100%
Successfully decoded 19 QR codes from 5 pages
Reassembling data...
Decompressing...

Recovered: recovered.bin (5,120 bytes)
Original file size: 5,120 bytes
Verification: PASS (MD5: ea4ca35ea7c1f774621e2191fad85b4c)
```

#### Error: Mixed Documents
```
Decoding: mixed_pages.pdf
Converting PDF to images...
Found 10 pages
Reading QR codes...
Successfully decoded 38 QR codes from 10 pages
Reassembling data...

Error: Mixed documents detected! Pages [15, 16, 17] have different MD5 hashes.
All pages must be from the same backup file.
```

#### Error: Missing Pages
```
Decoding: incomplete.pdf
Converting PDF to images...
Found 4 pages
Reading QR codes...
Successfully decoded 15 QR codes from 4 pages
Reassembling data...

Error: Missing pages in sequence: [3, 5]. Found pages [1, 2, 4, 6].
All pages from 1 to 6 must be present.
Use --recovery-mode to attempt partial recovery
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
