# CLAUDE.md - QR Code Backup Technical Reference

Quick reference for LLM agents working on this codebase.

---

## Project Overview

Python CLI tool for archiving data as QR codes on paper. Encodes files → PDF with QR codes. Decodes scanned PDFs → original files.

**Core Constraints:**
- 2×2 grid layout (4 QR codes per page) - NEVER CHANGE
- ~1.5 KB per PDF page @ 0.8mm density
- Files ≤ 25KB practical limit (17 pages @ 25KB)
- bzip2 compression (hardcoded)
- US Letter (215.9mm × 279.4mm)
- 5% parity overhead (default)

---

## Critical Functions

### calculate_optimal_qr_version()
Auto-calculates QR version from density. Searches v40→v1, finds largest version that fits ≥4 QR codes/page.
**DO NOT BREAK THIS** - ensures consistent 2×2 grid regardless of density.

### QR Version at Default Density (0.8mm)
Version 21 → 101 modules → 470 bytes/QR → 1,880 bytes/page raw → ~1.5 KB effective

---

## Binary Chunk Format (v2.1)

All chunks base64-encoded into QR codes.

**Data Page 1:**
```
[Enc:1][MD5:16][Page#:2][Parity:1][FileSize:4][EncMeta:72 if enc][CompressedSize:4 if parity][FileSize:4 if parity][Data]
```

**Other Data Pages:**
```
[Enc:1][MD5:16][Page#:2][Parity:1][Data]
```

**Parity Pages:**
```
[Enc:1][MD5:16][Page#:2][Parity:1][ParityIdx:2][TotalParity:2][TotalData:2][CompressedSize:4][FileSize:4][EncMeta:72 if enc][ParityData]
```

**Metadata Fields:**
- Enc: 0x00=unencrypted, 0x01=encrypted
- MD5: Hash of compressed (possibly encrypted) data - SAME on ALL pages
- Page#: 1-indexed, big-endian uint16
- Parity: 0x00=data, 0x01=parity
- All multi-byte: big-endian

**Metadata Overhead:**
- Data page 1 unenc: 24 bytes
- Data page 1 enc: 96 bytes
- Other data pages: 20 bytes
- Parity pages unenc: 34 bytes
- Parity pages enc: 106 bytes

**Limits:**
- Max file: 4GB (uint32)
- Max pages: 65,536 (uint16)

---

## Key Parameters

| Parameter | Default | Notes |
|-----------|---------|-------|
| Density | 0.8mm | QR module size. <0.8mm shows warning |
| Spacing | 5mm | Between QR codes |
| Margin | 20mm | Page margins |
| Header | 40mm | Always enabled |
| Border | 1 module | QR quiet zone (not 4-module standard) |
| Error Correction | M (15%) | L/M/Q/H available |
| Parity | 5.0% | ceil(parity% × pages) |

---

## Encryption (AES-256-GCM + Argon2id)

**Functions:** `derive_key()`, `encrypt_data()`, `decrypt_data()`, `verify_password()`

**Argon2id params:** time=3, memory=65536 (64MB), parallelism=4

**Page 1 encryption metadata (72 bytes):**
- Salt (16), time_cost (4), memory_cost (4), parallelism (4)
- Verification hash (32, BLAKE2b), Nonce (12)

**MD5 computed on ciphertext** - enables mixed document detection without password.

**Zero page overhead** - encryption metadata fits in existing chunk structure.

---

## Parity Recovery (Reed-Solomon)

**Vertical parity:** Byte-by-byte across chunks at each position.

**Key functions:**
- `calculate_parity_count()` - ceil(percent/100 × data_pages)
- `pad_chunks()` - Pad to uniform size for Reed-Solomon
- `generate_parity_chunks()` - Create parity using reedsolo
- `recover_missing_chunks()` - Erasure decoding with known missing positions

**Enhanced parity metadata (v2.1):**
- compressed_size (4 bytes) - for stripping padding after recovery
- file_size (4 bytes) - for page 1 recovery
- encryption metadata (72 bytes if encrypted) - for encrypted page 1 recovery

**Per-chunk padding removal:** Compute expected sizes from chunk_size and metadata overhead, strip padding from each recovered chunk individually before reassembly.

**N parity pages can recover ANY N missing data pages** - including page 1.

---

## Order-Independent Decoding & Mixed Document Detection

**Order-independent:** `reassemble_chunks()` sorts by page_number before reassembly.

**Mixed document detection:** During decode loop, establish reference MD5 from first chunk, fail immediately if any chunk has different MD5.

---

## Code Structure

```
qr_code_backup.py (~1800 lines)
├── Encryption (141-331): derive_key, encrypt_data, decrypt_data
├── Parity (337-543): calculate_parity_count, pad_chunks, generate/recover
├── Utility (58-140): calculate_optimal_qr_version, QR formulas, grid layout
├── Encoding (545-923): create_chunks, create_qr_code, generate_pdf
├── Decoding (1036-1658): parse_binary_chunk, reassemble_chunks
└── CLI (1660-1849): encode, decode, info commands
```

---

## Important Implementation Details

**ReportLab PDF:**
- Origin = bottom-left (Y counts up from bottom)
- Units: `value_mm * mm` (mm constant from reportlab)
- Images: Must wrap BytesIO in `ImageReader()`

**QR Module Formula:**
```python
modules = 4 * version + 17
physical_size = (modules + 2 * border) * module_size_mm
```

**Grid Layout:**
```python
cols = floor((width + spacing) / (qr_size + spacing))
rows = floor((height + spacing) / (qr_size + spacing))
# Must be 2×2 = 4 QR codes/page at default settings
```

**Chunk Size Calculation:**
```python
# At Version 21, M correction: ~470 bytes QR capacity
# Page 1 unenc: 470 - 24 = 446 bytes data
# Page 1 enc: 470 - 96 = 374 bytes data
# Other pages: 470 - 20 = 450 bytes data
```

---

## Validation & Error Handling

**Encoding:**
- File size check: `file_size > 2^32` → error
- Page count check: `total_chunks > 2^16` → error

**Decoding:**
1. MD5 consistency: All pages must match
2. Page sequence: 1,2,3...N no gaps
3. No duplicates
4. Page 1 required (unless parity recovery)
5. Final MD5 verification after reassembly

**Recovery Mode:** `--recovery-mode` skips validation, attempts reassembly with available pages.

---

## Tests

**Test files:** `tests/test_data/` - small.txt (54B), random_5kb.bin, random_25kb.bin

**Test suites (50 tests total):**
- `test_encryption.py` (16) - Key derivation, encrypt/decrypt, metadata parsing
- `test_parity.py` (19) - Calculation, padding, generation, recovery, metadata
- `test_parity_recovery_scenarios.py` (5) - Real-world damage scenarios, page 1 recovery
- `test_order_independence.py` (3) - Reversed/shuffled/interleaved pages
- `test_mixed_documents.py` (3) - Mixed document detection
- `test_combined_features.py` (4) - Feature integration

**Test helpers:** `tests/pdf_helpers.py` - reverse_pdf_pages, shuffle_pdf_pages, merge_pdfs, etc.

---

## CLI Commands

**Encode:**
```bash
python qr_code_backup.py encode <file> [--encrypt] [--density 0.8] [--parity-percent 5.0] [-o output.pdf]
```

**Decode:**
```bash
python qr_code_backup.py decode <pdf> -o <output> [--password PASS] [--recovery-mode]
```

**Info:**
```bash
python qr_code_backup.py info <pdf>
```

---

## Dependencies

**System:** libzbar0, poppler-utils, libgl1-mesa-glx, libglib2.0-0

**Python (requirements.txt):**
- qrcode, pyzbar, pillow, pdf2image, reportlab, click
- cryptography>=41.0.0 (AES-256-GCM)
- argon2-cffi>=23.1.0 (Argon2id)
- reedsolo>=1.7.0 (Reed-Solomon)
- pypdf (for test helpers)

---

## Known Issues & Limitations

**File size:** 25KB practical max (17 pages). Larger → too many pages to manage.

**Scan quality:** Requires 300 DPI, good lighting, flat pages, clean print.

**Compression:** bzip2 expands random/binary data. Tool handles gracefully (uses more pages).

**Python version:** 3.8+ required.

---

## Version History

**v2.1.0 (Current):** Enhanced parity (page 1 recovery), 0.8mm density, ~1.5 KB/page

**v2.0.0:** Parity pages, encryption, order-independent decoding, mixed document detection

**v1.0.0:** Auto QR version, 2×2 grid, binary format, bzip2

---

## Quick Start for LLM Agents

**Critical constraints:**
1. 2×2 grid (4 QR codes/page) - NEVER VIOLATE
2. `calculate_optimal_qr_version()` - maintains grid constraint
3. Binary format fields order - NEVER CHANGE (breaks compatibility)
4. MD5 on all pages - enables mixed document detection
5. Big-endian for multi-byte fields

**Test:**
```bash
pytest tests/ -v  # All 50 tests must pass
```

**Red flags:**
- Grid != 2×2 → Check calculate_optimal_qr_version()
- Decode fails → Check binary format field order
- MD5 mismatch → Check compression/encryption order
- Page 1 recovery fails → Check per-chunk padding removal

**Common tasks:**
- Add feature → Ensure 2×2 grid maintained, update binary format version if needed
- Change default → Update CLAUDE.md, README.md
- Optimize → Verify encode→decode→filecmp identical

---

**Last Updated:** 2025-10-21
