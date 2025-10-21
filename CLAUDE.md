# CLAUDE.md - QR Code Backup Project Documentation

## For Future LLM Agents

This document contains critical information about the QR Code Backup project architecture, design decisions, and implementation details that future LLM agents need to know when working on this codebase.

---

## Project Overview

**QR Code Backup** is a Python CLI tool for archiving digital data as QR codes printed on paper for long-term offline storage. It encodes files into multi-page PDFs containing QR codes with error correction, and can decode scanned PDFs back into the original files.

**Core Philosophy:**
- Optimized for files ≤ 25KB (practical limit for paper-based archival)
- Maintains consistent 2×2 grid layout (4 QR codes per page)
- Auto-calculates optimal QR version based on module density
- Hardcoded compression (bzip2) for simplicity
- US Letter paper as default (215.9mm × 279.4mm)

---

## Architecture Decisions

### 1. Auto-Calculated QR Version (Critical Feature)

**Problem Solved:** Users shouldn't need to manually specify QR version numbers.

**Solution:** `calculate_optimal_qr_version()` function that:
- Searches from QR version 40 down to 1
- Finds the **largest version** that still fits at least 4 QR codes per page (2×2 grid)
- Ensures consistent layout regardless of module density

**Why This Matters:**
- Changing module density changes physical QR size
- Smaller modules → can fit larger QR versions → more data per code
- Larger modules → must use smaller versions → less data per code
- Algorithm ensures we always use the optimal version for given density

**Implementation:**
```python
def calculate_optimal_qr_version(module_size_mm, page_width_mm, page_height_mm,
                                 margin_mm, spacing_mm, header_height_mm,
                                 min_qr_codes_per_page=4):
    # Try versions 40 down to 1
    for version in range(40, 0, -1):
        qr_size = calculate_qr_physical_size(version, module_size_mm)
        rows, cols = calculate_grid_layout(...)
        if (rows * cols) >= min_qr_codes_per_page:
            return version
    return 1
```

### 2. QR Code Border Reduction

**Changed:** Border from 4 modules (QR standard) to 1 module

**Rationale:**
- QR standard recommends 4-module "quiet zone"
- Modern scanners work fine with 1 module
- Saves 6mm per QR code (significant at small densities)
- Allows fitting larger QR versions at same module size

**Location:** `create_qr_code()` and `calculate_qr_physical_size()` both use `border=1`

### 3. Hardcoded Compression (bzip2)

**Decision:** Removed `--compression` option, always use bzip2

**Rationale:**
- Simplifies user experience
- bzip2 generally better than gzip for most data
- Random/binary data won't compress much anyway (users should check file size)
- Less configuration = fewer mistakes

**Note:** If file grows after compression, tool still works - just uses more QR codes

### 4. Horizontal Centering

**Feature:** QR codes are centered horizontally on the page

**Implementation:**
```python
grid_width = cols * qr_size + (cols - 1) * spacing
available_width = page_width - 2 * margin
horizontal_offset = (available_width - grid_width) / 2
x = margin + horizontal_offset + col * (qr_size + spacing)
```

**Why:** Professional appearance, reduces appearance of wasted whitespace

---

## Key Parameters & Defaults

### Module Size: 0.9mm (default)

**Evolution:**
- Started at 1.2mm (very safe)
- Reduced to 1.0mm (good balance)
- **Final: 0.9mm** (optimal balance)

**Rationale:**
- Still above 0.8mm warning threshold
- Small enough for good data density
- Large enough for reliable scanning
- Results in Version 18 QR codes with default settings

**Warning System:**
- If user specifies < 0.8mm, display warning about data loss risk
- No hard limit - users can go lower if they want (at their own risk)

### Spacing: 5mm (default)

**Evolution:** 10mm → 5mm

**Rationale:**
- 10mm was excessive whitespace
- 5mm is adequate separation for scanning
- Allows QR codes to be slightly larger for same page

### Margin: 20mm (default)

**Rationale:**
- Standard margin for printable area
- Most printers can't print to edge anyway
- Configurable if user needs different value

### Page Size: US Letter (215.9mm × 279.4mm)

**Decision:** Changed from A4 to US Letter as default

**Rationale:**
- More common in US
- Configurable via `--page-width` and `--page-height`

### Header Height: 40mm (when enabled)

**Contents:**
- Title (filename or custom)
- Page X of Y
- Decode instructions
- Horizontal line separator

**Configurable:** `--no-header` flag to disable

---

## Data Format

Each QR code contains a JSON structure:

```json
{
  "format_version": "1.0",
  "file_name": "original.bin",
  "file_size": 25600,
  "total_pages": 37,
  "page_number": 1,
  "chunk_size": 314,
  "checksum_type": "sha256",
  "file_checksum": "abc123...",
  "chunk_checksum": "def456...",
  "compression": "bzip2",
  "data": "<base64_encoded_chunk>"
}
```

**Critical Fields:**
- `page_number`: 1-indexed, used for reassembly
- `total_pages`: Allows detection of missing pages
- `file_checksum`: SHA-256 of original uncompressed file
- `chunk_checksum`: SHA-256 of this chunk's data (before base64)
- `data`: Base64-encoded compressed chunk

**Metadata Overhead:** ~300 bytes per QR code (accounted for in `calculate_chunk_size`)

---

## QR Code Capacity Estimation

**Formula Used:**
```python
def get_qr_capacity(qr_version, error_correction):
    # Simplified lookup table with interpolation
    # Binary mode capacities
```

**Key Versions:**
- Version 1: 17 modules, ~14 bytes (M correction)
- Version 15: 77 modules, ~530 bytes (M correction)
- Version 18: 85 modules, ~314 bytes actual after overhead (M correction)
- Version 25: 117 modules, ~718 bytes actual after overhead (M correction)
- Version 40: 177 modules, ~2331 bytes (M correction)

**Actual Capacity After Overhead:**
- QR capacity - 300 bytes (JSON metadata) - 33% (base64 encoding)

---

## Error Correction Levels

| Level | Recovery | Capacity Impact | Use Case |
|-------|----------|-----------------|----------|
| **L** | ~7% | Highest | Perfect conditions only |
| **M** | ~15% | Good | **Default** - General use |
| **Q** | ~25% | Reduced | Moderate damage expected |
| **H** | ~30% | Lowest | Maximum protection |

**Current Default:** M (15% recovery)

**Rationale:** Good balance between data capacity and error correction

---

## Testing Strategy

### Test Files Created

Located in `tests/test_data/`:
- `small.txt` - 54 bytes (basic functionality)
- `random_5kb.bin` - 5KB (typical use case)
- `random_25kb.bin` - 25KB (maximum recommended)

**Large files removed:** 500KB, 2MB, 10MB (impractical for paper archival)

### Test Coverage

**Unit Tests:**
- `tests/test_encode.py` - Encoding functions
- `tests/test_decode.py` - Decoding functions
- `tests/test_integration.py` - Full encode-decode cycles

**Integration Tests:**
- Encode → Decode → Verify cycle
- Different file sizes
- Different compression methods
- Missing page detection
- Checksum verification

**Physical Testing (Recommended):**
1. Encode a file
2. Print PDF on actual paper (300 DPI)
3. Scan back to PDF
4. Decode and verify checksum

---

## Important Implementation Details

### 1. PDF Generation (ReportLab)

**Key Points:**
- Uses reportlab units (points)
- 1mm = reportlab's `mm` constant
- Must convert all measurements: `value_mm * mm`
- Canvas origin is bottom-left (not top-left!)
- Y-coordinates count from bottom up

**QR Code Placement:**
```python
# Top of page
y_top = page_height - header_height - margin

# Each QR code row
y = y_top - (row + 1) * qr_size - row * spacing
```

### 2. Image Embedding in PDF

**Issue:** Can't pass BytesIO directly to `drawImage()`

**Solution:** Use `ImageReader` wrapper:
```python
from reportlab.lib.utils import ImageReader
c.drawImage(ImageReader(img_buffer), x, y, width, height)
```

### 3. QR Code Module Formula

**QR Code Size Formula:**
```python
modules_per_side = 4 * version + 17

# Version 1: 4*1 + 17 = 21 modules
# Version 15: 4*15 + 17 = 77 modules
# Version 40: 4*40 + 17 = 177 modules
```

**Physical Size:**
```python
total_modules = modules_per_side + 2 * border
physical_size_mm = total_modules * module_size_mm
```

### 4. Grid Layout Calculation

**Formula:**
```python
# Add spacing to available space because last QR doesn't need trailing spacing
cols = floor((available_width + spacing) / (qr_size + spacing))
rows = floor((available_height + spacing) / (qr_size + spacing))
```

**Example:**
- Available width: 175.9mm
- QR size: 83mm
- Spacing: 5mm
- Columns: floor((175.9 + 5) / (83 + 5)) = floor(180.9 / 88) = 2

---

## Known Limitations

### 1. File Size Limit

**Practical Limit:** ~25KB

**Rationale:**
- 25KB @ 0.9mm module = ~37 pages
- Larger files = too many pages to print/scan/manage
- Users should compress or split larger files externally

### 2. Scan Quality Dependency

**Requires:**
- 300 DPI minimum scan resolution
- Good lighting
- Flat pages (no wrinkles)
- Clean printer output

**Recommendation:** Test a sample page before archiving critical data

### 3. Compression Limitations

**bzip2 doesn't help with:**
- Already compressed files (zip, jpg, mp4, etc.)
- Random binary data (encryption keys, random data)
- Small files (overhead > savings)

**Tool handles this gracefully:** Just uses more QR codes

### 4. Python/Library Version Dependencies

**Critical:**
- Python 3.8+ required
- pyzbar requires libzbar0 system library
- pdf2image requires poppler-utils
- See requirements.txt for Python packages

---

## Common Issues & Solutions

### Issue: "Unable to find zbar shared library"

**Solution:**
```bash
# Linux
sudo apt-get install libzbar0

# macOS
brew install zbar
```

### Issue: "Unable to convert PDF"

**Solution:**
```bash
# Linux
sudo apt-get install poppler-utils

# macOS
brew install poppler
```

### Issue: QR codes not scanning from printed page

**Possible causes:**
1. Print resolution too low (need 300+ DPI)
2. Module size too small (try 1.0mm or 1.2mm)
3. Paper quality issues
4. Printer alignment/quality issues

**Solution:** Use larger module size (`--module-size 1.2`)

### Issue: File larger after compression

**Cause:** Random/binary data doesn't compress well

**Solution:** This is normal - tool will still work, just use more QR codes

---

## Future Enhancement Ideas

### High Priority

1. **Progressive encoding** - Resume interrupted encode/decode
2. **Parity pages** - Reed-Solomon at file level for missing page recovery
3. **Batch processing** - Multiple files in one operation
4. **Setup.py/PyPI** - Package for `pip install qr_code_backup`

### Medium Priority

1. **Alternative page sizes** - Add A4, Legal presets
2. **Encryption option** - Built-in encryption before encoding
3. **Web interface** - Browser-based version
4. **Mobile app** - Decode using smartphone camera

### Low Priority

1. **Color QR codes** - Higher density (experimental, risky)
2. **Custom error correction per file type** - Auto-select based on file
3. **Metadata file** - Separate file with checksums for verification

---

## Command-Line Interface

### Encode Command

```bash
python qr_code_backup.py encode <file> [OPTIONS]

Options:
  -o, --output PATH          Output PDF path
  --error-correction L|M|Q|H Error correction level [default: M]
  --module-size FLOAT        QR module size in mm [default: 0.9]
  --page-width FLOAT         Page width in mm [default: 215.9]
  --page-height FLOAT        Page height in mm [default: 279.4]
  --margin FLOAT             Page margin in mm [default: 20]
  --spacing FLOAT            QR code spacing in mm [default: 5]
  --title TEXT               Custom title for headers
  --no-header                Disable page headers
```

### Decode Command

```bash
python qr_code_backup.py decode <pdf> [OPTIONS]

Options:
  -o, --output PATH      Output file path
  --verify               Verify checksums [default: enabled]
  --recovery-mode        Attempt recovery from missing pages
  --force                Overwrite existing file
```

### Info Command

```bash
python qr_code_backup.py info <pdf>
```

Displays metadata without decoding.

---

## Code Structure

```
qr_code_backup.py (main file, 760+ lines)
├── Imports & Constants
├── Utility Functions
│   ├── calculate_checksum()
│   ├── compress_data() / decompress_data()
│   ├── get_qr_modules()
│   ├── calculate_qr_physical_size()
│   ├── calculate_grid_layout()
│   └── calculate_optimal_qr_version() ← KEY FUNCTION
├── Encoding Functions
│   ├── get_qr_capacity()
│   ├── calculate_chunk_size()
│   ├── create_chunks()
│   ├── create_qr_code()
│   └── generate_pdf()
├── Decoding Functions
│   ├── pdf_to_images()
│   ├── decode_qr_codes_from_image()
│   ├── parse_qr_data()
│   └── reassemble_chunks()
└── CLI Commands
    ├── encode()
    ├── decode()
    └── info()
```

---

## Performance Characteristics

**Encoding Speed:**
- ~50-100 QR codes/second
- 5KB file (26 codes): ~1-2 seconds
- 25KB file (80 codes): ~3-5 seconds

**Decoding Speed:**
- ~10-30 QR codes/second (depends on scan quality)
- 5KB file: ~5-10 seconds
- 25KB file: ~15-30 seconds

**Memory Usage:**
- Typical: 100-500 MB
- Loads entire file into memory
- Not suitable for multi-GB files

---

## Testing Checklist for Changes

When modifying the code, test:

1. ✅ Basic encode-decode cycle
2. ✅ Different module sizes (0.7, 0.9, 1.2mm)
3. ✅ Different file sizes (1KB, 5KB, 25KB)
4. ✅ Error correction levels (L, M, Q, H)
5. ✅ Custom page dimensions
6. ✅ With and without headers
7. ✅ Recovery mode with missing pages
8. ✅ Checksum verification
9. ✅ Warning for module size < 0.8mm
10. ✅ Grid layout is always 2×2

---

## Version History

### v1.0.0 (Current)
- Auto-calculated QR version
- 0.9mm default module size
- 2×2 grid layout (4 QR codes per page)
- Hardcoded bzip2 compression
- Horizontal centering
- 1-module QR border
- 5mm default spacing
- US Letter default page size

---

## License

MIT License - See LICENSE file

---

## For Future LLM Agents: Quick Start

**If asked to modify this project:**

1. **Read this file first** - Contains critical design decisions
2. **Key function:** `calculate_optimal_qr_version()` - Don't break this!
3. **Test with:** `tests/test_data/random_5kb.bin`
4. **Expected output:** 2×2 grid, 4 QR codes per page
5. **Verify:** Encode → Decode → Check files match

**Common requests:**
- "Add feature X" → Check if it conflicts with 2×2 grid requirement
- "Change default" → Document why in this file
- "Optimize" → Ensure still maintains data integrity
- "Support larger files" → Explain 25KB practical limit

**Red flags:**
- QR codes not fitting 2×2 grid → Check `calculate_optimal_qr_version()`
- Files don't match after decode → Check compression/decompression
- Pages have wrong layout → Check `generate_pdf()` calculations

---

**Last Updated:** 2025-10-21
**Maintained for:** Future LLM agents working on QR Code Backup
