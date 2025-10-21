# QR Code Backup - Implementation and Testing Plan

## Project Structure

```
qr_code_backup/
├── qr_code_backup.py          # Main executable script
├── requirements.txt           # Python dependencies
├── setup.py                   # Package installation config
├── README.md                  # User documentation
├── QR_CODE_BACKUP.md         # Specification (already created)
├── tests/                     # Test suite
│   ├── __init__.py
│   ├── test_encode.py        # Encoding tests
│   ├── test_decode.py        # Decoding tests
│   ├── test_integration.py   # End-to-end tests
│   └── test_data/            # Sample files for testing
│       ├── small.txt         # < 1 KB
│       ├── medium.bin        # ~100 KB
│       └── large.zip         # ~1 MB
└── examples/                  # Example outputs
    └── sample_output.pdf
```

## Implementation Phases

### Phase 1: Project Setup and Core Infrastructure (1-2 hours)

**Tasks:**
1. Create project directory structure
2. Initialize `requirements.txt` with dependencies:
   ```
   qrcode>=7.4
   Pillow>=10.0
   pypdf>=3.0
   pyzbar>=0.1.9
   opencv-python>=4.8
   reportlab>=4.0
   click>=8.0
   ```
3. Create basic `qr_code_backup.py` skeleton with CLI framework
4. Implement argument parsing using Click
5. Create help text and usage examples
6. Add version and format constants

**Deliverables:**
- Working CLI that displays help text
- All dependencies installable via `pip install -r requirements.txt`

**Testing:**
- Run `python qr_code_backup.py --help` to verify CLI
- Verify all imports work correctly

---

### Phase 2: Data Chunking and Metadata (2-3 hours)

**Tasks:**
1. Implement file reading and chunking logic
2. Create metadata structure (JSON format from spec)
3. Implement checksum calculation (SHA-256)
4. Calculate optimal chunk size based on QR parameters
5. Add compression support (gzip, bzip2, none)
6. Implement Base64 encoding for binary safety

**Key Functions:**
```python
def calculate_chunk_size(qr_version, error_correction):
    """Calculate max data bytes per QR code after overhead"""
    pass

def create_chunks(file_path, chunk_size, compression='gzip'):
    """Split file into chunks with metadata"""
    pass

def calculate_checksum(data, algorithm='sha256'):
    """Calculate hash of data"""
    pass
```

**Deliverables:**
- Functions that split any file into numbered chunks
- Each chunk has complete metadata
- Checksums calculated for file and chunks

**Testing:**
- Test with files of various sizes (1 KB, 100 KB, 1 MB)
- Verify chunk boundaries
- Confirm checksums are reproducible
- Test all compression methods

---

### Phase 3: QR Code Generation (2-3 hours)

**Tasks:**
1. Implement QR code generation from chunk metadata
2. Configure QR version and error correction levels
3. Generate PIL Image objects for each QR code
4. Optimize QR code size/DPI settings
5. Handle errors for data exceeding QR capacity

**Key Functions:**
```python
def create_qr_code(data_dict, qr_version, error_correction):
    """Generate QR code image from metadata dictionary"""
    pass

def get_qr_capacity(qr_version, error_correction):
    """Return max bytes for given QR parameters"""
    pass
```

**Deliverables:**
- Generate QR codes from JSON metadata
- Support all error correction levels (L, M, Q, H)
- QR codes are clear and scannable at 300 DPI

**Testing:**
- Generate QR codes with various data sizes
- Verify error correction levels are applied
- Test QR code capacity limits
- Scan generated codes with phone to verify readability

---

### Phase 4: PDF Generation (3-4 hours)

**Tasks:**
1. Set up ReportLab PDF canvas
2. Implement page layout (margins, spacing, grid)
3. Create header text with metadata
4. Position QR codes in grid (default 3x3)
5. Support multiple page sizes (A4, Letter, Legal)
6. Add page numbering
7. Optimize for printing quality

**Key Functions:**
```python
def create_pdf_page(canvas, qr_images, page_num, total_pages, config):
    """Draw QR codes and header on a single PDF page"""
    pass

def generate_pdf(qr_images, output_path, title, config):
    """Create multi-page PDF from QR code images"""
    pass
```

**Deliverables:**
- Multi-page PDF output
- Professional-looking headers
- Properly spaced QR codes
- Print-ready quality (300+ DPI)

**Testing:**
- Generate PDFs with 1, 10, and 100 pages
- Verify page headers are correct
- Print and visually inspect quality
- Test different page sizes

---

### Phase 5: Encode Command Implementation (2 hours)

**Tasks:**
1. Integrate all encoding components
2. Add progress bar for user feedback
3. Implement all CLI options (--dpi, --qr-size, etc.)
4. Add validation for parameters
5. Create summary output after encoding
6. Handle encoding errors gracefully

**Key Function:**
```python
def encode_command(input_file, output_path, **options):
    """Main encode workflow"""
    # 1. Read and validate input file
    # 2. Calculate chunks
    # 3. Generate QR codes
    # 4. Create PDF
    # 5. Display summary
    pass
```

**Deliverables:**
- Fully functional `encode` command
- All options working as specified
- Clear progress indication
- Helpful error messages

**Testing:**
- Encode files with various options
- Test error handling (missing file, invalid params)
- Verify output file integrity
- Test with edge cases (empty file, very large file)

---

### Phase 6: QR Code Decoding from Images (3-4 hours)

**Tasks:**
1. Implement PDF to image conversion
2. Use pyzbar to detect and decode QR codes
3. Handle multiple QR codes per page
4. Implement image preprocessing (rotation correction, contrast)
5. Parse JSON from decoded QR data
6. Handle decode failures gracefully

**Key Functions:**
```python
def pdf_to_images(pdf_path):
    """Convert PDF pages to PIL Images"""
    pass

def decode_qr_codes_from_image(image):
    """Find and decode all QR codes in an image"""
    pass

def parse_qr_data(qr_string):
    """Parse JSON metadata from QR code string"""
    pass
```

**Deliverables:**
- Decode QR codes from PDF pages
- Extract JSON metadata
- Handle scan quality variations

**Testing:**
- Decode clean generated PDFs
- Test with scanned PDFs (if available)
- Test with rotated/skewed images
- Test error handling for unreadable codes

---

### Phase 7: Data Reassembly (2-3 hours)

**Tasks:**
1. Collect all decoded chunks
2. Sort by page number
3. Verify page sequence (detect missing pages)
4. Validate chunk checksums
5. Concatenate data chunks
6. Decompress if needed
7. Verify final file checksum
8. Write output file

**Key Functions:**
```python
def reassemble_chunks(chunks):
    """Sort and validate chunks, reassemble file"""
    pass

def verify_integrity(chunks, final_data):
    """Check all checksums match"""
    pass
```

**Deliverables:**
- Reconstruct original file from chunks
- Detect missing or damaged pages
- Verify data integrity

**Testing:**
- Full encode-decode cycle with various files
- Intentionally remove pages to test detection
- Verify checksum validation works
- Test with compressed data

---

### Phase 8: Decode Command Implementation (2-3 hours)

**Tasks:**
1. Integrate all decoding components
2. Add progress indication
3. Implement recovery mode for partial data
4. Add verification mode with detailed output
5. Handle all error cases
6. Create detailed decode report

**Key Function:**
```python
def decode_command(input_pdf, output_path, **options):
    """Main decode workflow"""
    # 1. Load PDF
    # 2. Decode all QR codes
    # 3. Validate and sort chunks
    # 4. Reassemble file
    # 5. Verify checksums
    # 6. Display report
    pass
```

**Deliverables:**
- Fully functional `decode` command
- Clear error messages for failures
- Detailed verification reports
- Recovery mode for damaged archives

**Testing:**
- Decode various encoded files
- Test with missing pages
- Test recovery mode
- Test verification output

---

### Phase 9: Info Command and Polish (1-2 hours)

**Tasks:**
1. Implement `info` command to read metadata
2. Display encoding parameters, file info
3. Add better error messages throughout
4. Improve progress bars and user feedback
5. Add color to terminal output (optional)
6. Create comprehensive `--help` documentation

**Key Function:**
```python
def info_command(pdf_path):
    """Display metadata about encoded PDF"""
    pass
```

**Deliverables:**
- Working `info` command
- Professional CLI experience
- Comprehensive help text

**Testing:**
- Run info on various PDFs
- Verify all metadata is displayed
- Test help documentation

---

### Phase 10: Documentation (2 hours)

**Tasks:**
1. Write comprehensive README.md:
   - Installation instructions
   - Quick start guide
   - Command reference
   - Examples
   - Troubleshooting
2. Add docstrings to all functions
3. Create example workflows
4. Document system dependencies (libzbar0)
5. Add contribution guidelines (if open source)

**Deliverables:**
- Complete README.md
- Well-documented code
- Example command sequences

---

### Phase 11: Testing Suite (3-4 hours)

**Tasks:**
1. Create test data files (small, medium, large)
2. Write unit tests for core functions:
   - Chunking
   - Checksum calculation
   - QR code generation
   - Metadata parsing
3. Write integration tests:
   - Full encode workflow
   - Full decode workflow
   - Error cases
4. Create physical test (optional):
   - Encode → Print → Scan → Decode
5. Performance benchmarks

**Test Structure:**
```python
# test_encode.py
def test_file_chunking():
    """Test file is split correctly"""
    pass

def test_checksum_calculation():
    """Test checksum consistency"""
    pass

def test_qr_generation():
    """Test QR codes are created"""
    pass

# test_decode.py
def test_qr_decoding():
    """Test QR codes can be read"""
    pass

def test_chunk_reassembly():
    """Test chunks reassemble correctly"""
    pass

# test_integration.py
def test_full_cycle():
    """Test encode → decode → verify"""
    pass

def test_missing_page_detection():
    """Test missing page handling"""
    pass

def test_damaged_qr_recovery():
    """Test error correction works"""
    pass
```

**Deliverables:**
- Comprehensive test suite
- >80% code coverage
- All tests passing

**Testing:**
- Run: `pytest tests/ -v`
- Check coverage: `pytest --cov=qr_code_backup`

---

## Testing Strategy

### Unit Testing

**Encoding Components:**
- [x] File chunking with various sizes
- [x] Metadata generation
- [x] Checksum calculation
- [x] QR code generation
- [x] Compression/decompression
- [x] PDF page creation

**Decoding Components:**
- [x] PDF to image conversion
- [x] QR code detection
- [x] JSON parsing
- [x] Chunk sorting
- [x] Data reassembly
- [x] Checksum verification

### Integration Testing

**Happy Path:**
1. Encode small text file (1 KB) → Decode → Verify match
2. Encode medium binary file (100 KB) → Decode → Verify match
3. Encode large compressed file (1 MB) → Decode → Verify match

**Error Handling:**
1. Encode with invalid parameters → Check error message
2. Decode PDF with missing page → Detect and report
3. Decode PDF with damaged QR code → Use error correction or fail gracefully
4. Decode non-QR PDF → Fail with clear message

**Options Testing:**
1. Test all error correction levels
2. Test different page sizes
3. Test with/without compression
4. Test custom titles and headers
5. Test different QR versions

### Physical Testing (Optional but Recommended)

1. Encode a known file (e.g., test image)
2. Generate PDF
3. Print on actual paper (300 DPI recommended)
4. Scan back to PDF using standard scanner
5. Decode scanned PDF
6. Verify output matches input
7. Test degradation: crumple page slightly, rescan, decode

### Performance Testing

**Benchmarks:**
- Encoding speed: QR codes per second
- Decoding speed: QR codes per second
- File size overhead: output PDF size vs input file
- Memory usage during operations

**Target Performance:**
- Encode 100-page doc in < 30 seconds
- Decode 100-page doc in < 60 seconds
- Memory usage < 500 MB for 10 MB file

---

## Implementation Checklist

### Core Functionality
- [ ] CLI framework with Click
- [ ] Encode command fully functional
- [ ] Decode command fully functional
- [ ] Info command functional
- [ ] All command-line options working
- [ ] Progress bars and user feedback
- [ ] Error handling comprehensive

### Encoding Features
- [ ] File chunking
- [ ] Metadata generation
- [ ] QR code creation (all error levels)
- [ ] PDF generation (multi-page)
- [ ] Page headers with metadata
- [ ] Compression support
- [ ] Checksum calculation

### Decoding Features
- [ ] PDF to image conversion
- [ ] QR code detection and decoding
- [ ] Chunk reassembly
- [ ] Checksum verification
- [ ] Missing page detection
- [ ] Decompression support
- [ ] Recovery mode

### Quality
- [ ] Comprehensive help text
- [ ] All dependencies documented
- [ ] README with examples
- [ ] Code well-commented
- [ ] Unit tests written
- [ ] Integration tests written
- [ ] All tests passing
- [ ] Physical print test successful

### Polish
- [ ] Clean error messages
- [ ] Consistent output formatting
- [ ] Version information
- [ ] Example files included

---

## Estimated Timeline

| Phase | Description | Time | Cumulative |
|-------|-------------|------|------------|
| 1 | Project setup | 1-2h | 2h |
| 2 | Data chunking | 2-3h | 5h |
| 3 | QR generation | 2-3h | 8h |
| 4 | PDF generation | 3-4h | 12h |
| 5 | Encode command | 2h | 14h |
| 6 | QR decoding | 3-4h | 18h |
| 7 | Data reassembly | 2-3h | 21h |
| 8 | Decode command | 2-3h | 24h |
| 9 | Info & polish | 1-2h | 26h |
| 10 | Documentation | 2h | 28h |
| 11 | Testing suite | 3-4h | 32h |

**Total estimated time: 28-32 hours** for a complete, well-tested implementation.

For an MVP (Minimum Viable Product), phases 1-8 are essential (~24 hours).

---

## Success Criteria

**Functional Requirements:**
- ✓ Successfully encode files from 1 KB to 10 MB
- ✓ Successfully decode clean PDFs (not scanned)
- ✓ Successfully decode scanned PDFs at 300 DPI
- ✓ Detect missing or damaged pages
- ✓ All error correction levels work
- ✓ All command-line options functional

**Quality Requirements:**
- ✓ Code coverage > 80%
- ✓ All tests pass
- ✓ Clear documentation
- ✓ No crashes on invalid input
- ✓ Helpful error messages

**Performance Requirements:**
- ✓ Encode 50-page doc in < 1 minute
- ✓ Decode 50-page doc in < 2 minutes
- ✓ Handle files up to 10 MB

**Physical Verification:**
- ✓ Print and scan test successful
- ✓ Survives minor paper damage with error correction

---

## Next Steps

1. Review this plan and specification
2. Get approval to proceed with implementation
3. Set up development environment
4. Begin Phase 1: Project setup

Would you like me to proceed with implementation?
