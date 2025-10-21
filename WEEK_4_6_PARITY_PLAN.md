# Week 4-6: Parity Pages Implementation Plan
## Phase 2 Feature: Reed-Solomon Parity Recovery

**Feature:** PAR2-like parity pages using Reed-Solomon erasure codes for recovering from missing/damaged pages

**Timeline:** 3 weeks (Days 1-15)

**Status:** Planning

---

## Overview

### Problem Statement

Physical backups on paper can degrade over time or pages can be lost. Currently, if even a single page is missing or damaged beyond QR code error correction, the entire backup is unrecoverable.

### Solution

Add optional parity pages using Reed-Solomon erasure codes that enable recovery of up to N missing pages if N parity pages exist. This provides redundancy at the document level.

### Use Cases

- Long-term archival where physical degradation is expected
- Large documents where losing a few pages is statistically likely
- Critical data requiring maximum redundancy
- Protection against coffee spills, torn pages, or lost sheets

---

## Design Overview

### Reed-Solomon Erasure Codes

**How it works:**
- Each data chunk is treated as a "symbol"
- Parity symbols are computed across all data chunks using Reed-Solomon
- Can recover N missing chunks with N parity chunks
- Works at byte-level across the entire document

**Example:**
```
Data pages:   [D1] [D2] [D3] [D4] [D5]
Parity pages: [P1] [P2]

Can recover any 2 missing pages using the parity data
```

### Default Parity Configuration

**Formula:** `ceil(num_data_pages / 20)`

**Examples:**
- 1-20 pages → 1 parity page (5% overhead)
- 21-40 pages → 2 parity pages (5-10% overhead)
- 100 pages → 5 parity pages (5% overhead)

**Rationale:**
- Balances protection vs overhead
- For typical 25KB file (~20 pages), adds 1 extra page
- User can override with `--parity-pages N`

### Pipeline Integration

**Current pipeline:**
```
Read → Compress → [Encrypt] → Chunk → QR encode → PDF
```

**With parity:**
```
Read → Compress → [Encrypt] → Chunk → [Generate Parity] → QR encode → PDF
                                         ↓
                                   Data chunks + Parity chunks
```

**Key decision:** Parity is computed AFTER encryption (on ciphertext), so parity pages don't leak information about plaintext.

---

## Binary Format Changes

### Parity Page Metadata

**Data page format (updated):**
```
[Encryption Flag: 1 byte]
[MD5: 16 bytes]
[Page#: 2 bytes]
[Parity Flag: 1 byte]     ← NEW: 0x00 for data page
[FileSize: 4 bytes]       ← Only on page 1
[Encryption metadata...]  ← Only if encrypted on page 1
[Data: variable]
```

**Parity page format:**
```
[Encryption Flag: 1 byte]
[MD5: 16 bytes]           ← Same MD5 as data pages
[Page#: 2 bytes]          ← Continues sequence (e.g., page 21 of 21)
[Parity Flag: 1 byte]     ← 0x01 for parity page
[Parity Index: 2 bytes]   ← Which parity page (0-indexed)
[Total Parity: 2 bytes]   ← Total number of parity pages
[Total Data: 2 bytes]     ← Total number of data pages
[Parity Data: variable]   ← Reed-Solomon parity bytes
```

### Overhead Analysis

- **Data pages:** +1 byte per page (parity flag)
- **Parity pages:** +9 bytes metadata per parity page
- **Total document:** +5% pages (typical configuration)

---

## Implementation Plan

### Week 4 (Days 1-5): Core Parity Functions

**Day 1: Setup & Research**
- [ ] Add dependency: `reedsolo>=1.7.0` to requirements.txt
- [ ] Install and test reedsolo library
- [ ] Research Reed-Solomon API and best practices
- [ ] Create `tests/test_parity.py` skeleton

**Day 2: Parity Generation**
- [ ] Implement `calculate_parity_count(num_data_pages, parity_pages=None)`
- [ ] Implement `pad_chunks(chunks)` - Pad all chunks to same size
- [ ] Implement `generate_parity_chunks(data_chunks, num_parity)` using Reed-Solomon
- [ ] Unit tests for parity generation (4 tests):
  - Test parity count calculation
  - Test chunk padding
  - Test parity generation (verify output structure)
  - Test different parity counts

**Day 3: Parity Recovery**
- [ ] Implement `recover_missing_chunks(all_chunks, parity_chunks, num_data_chunks)`
- [ ] Unit tests for parity recovery (5 tests):
  - Test single missing chunk recovery
  - Test multiple missing chunks recovery
  - Test no missing chunks (no-op)
  - Test too many missing chunks (should error)
  - Test edge case: last page missing

**Day 4: Binary Metadata Integration**
- [ ] Update `parse_binary_chunk()` to parse parity flag and metadata
- [ ] Add parity flag to chunk creation in `create_chunks()`
- [ ] Unit tests for metadata parsing (3 tests):
  - Parse data page with parity flag=0x00
  - Parse parity page with full metadata
  - Parse parity page metadata structure

**Day 5: Testing & Refinement**
- [ ] Run all unit tests (target: 12 tests passing)
- [ ] Fix any issues found during testing
- [ ] Performance benchmark: parity generation for 100 pages
- [ ] Code review and cleanup

### Week 5 (Days 6-10): Integration into Encode/Decode

**Day 6: Encode Integration**
- [ ] Modify `create_chunks()` to support `parity_pages` parameter
- [ ] Add parity chunk generation after data chunks
- [ ] Build parity chunks with metadata headers
- [ ] Update chunk count calculations
- [ ] Unit test: create_chunks() with parity=True

**Day 7: Decode Integration - Parsing**
- [ ] Modify `reassemble_chunks()` to separate data and parity chunks
- [ ] Detect presence of parity pages
- [ ] Identify missing data pages
- [ ] Display parity information to user
- [ ] Unit test: reassemble_chunks() recognizes parity

**Day 8: Decode Integration - Recovery**
- [ ] Implement parity recovery flow in `reassemble_chunks()`
- [ ] Call `recover_missing_chunks()` when pages missing
- [ ] Handle recovery success/failure
- [ ] Update report with recovery statistics
- [ ] Integration test: encode → remove page → decode with recovery

**Day 9: Validation & Error Handling**
- [ ] Validate parity pages have same MD5 as data pages
- [ ] Handle edge case: all parity pages missing
- [ ] Handle edge case: more missing than can recover
- [ ] Graceful fallback if recovery fails in recovery mode
- [ ] Integration tests for error cases (3 tests):
  - Too many missing pages
  - Parity pages from different document
  - Corrupted parity data

**Day 10: Testing & Validation**
- [ ] Integration test: full cycle with 1 parity page
- [ ] Integration test: full cycle with multiple parity pages
- [ ] Integration test: recovery from middle page missing
- [ ] Integration test: recovery from last page missing
- [ ] Target: 10 integration tests passing

### Week 6 (Days 11-15): CLI, Documentation, and Final Testing

**Day 11: CLI Integration**
- [ ] Add `--parity` flag to encode command (uses default count)
- [ ] Add `--parity-pages N` option for custom count
- [ ] Display parity information during encoding
- [ ] Display recovery information during decoding
- [ ] Update info command to show parity page count

**Day 12: PDF Header Updates**
- [ ] Update `generate_pdf()` to mark parity pages in header
- [ ] Header text: "Page 21 of 21 - PARITY PAGE 1 of 1"
- [ ] Ensure parity pages are visually distinct
- [ ] Manual test: print PDF and verify headers

**Day 13: Combined Feature Testing**
- [ ] Test parity + encryption (encode encrypted with parity)
- [ ] Test parity + encryption + recovery (decrypt after recovery)
- [ ] Test parity + order-independent decoding (shuffled pages with recovery)
- [ ] Test parity + mixed document detection (parity pages with wrong MD5)
- [ ] Target: 4 combined feature tests passing

**Day 14: Documentation**
- [ ] Update README.md with parity examples
- [ ] Update CLAUDE.md with parity implementation details
- [ ] Add parity to feature list
- [ ] Document CLI options
- [ ] Document binary format changes
- [ ] Create usage examples

**Day 15: Final Validation & Manual Testing**
- [ ] Run full test suite (target: 26+ tests passing)
- [ ] Manual test: encode 25KB file with parity
- [ ] Manual test: remove page and recover
- [ ] Manual test: print, scan, remove page, recover
- [ ] Performance validation: < 10 seconds encode with parity
- [ ] Performance validation: < 15 seconds decode with recovery
- [ ] Code review and cleanup
- [ ] Commit parity implementation

---

## Technical Specifications

### Parity Generation Algorithm

**Vertical parity across chunks:**

```python
def generate_parity_chunks(data_chunks: List[bytes], num_parity: int) -> List[bytes]:
    """
    Generate parity using Reed-Solomon erasure codes.

    Approach: Compute parity "vertically" across chunks
    - For each byte position (0 to chunk_size-1):
      - Collect byte from that position in all data chunks
      - Compute Reed-Solomon parity bytes
      - Store in corresponding parity chunks

    Example (4 data chunks, 1 parity chunk, 3 bytes each):

    Data:    D1[A,B,C]  D2[D,E,F]  D3[G,H,I]  D4[J,K,L]
                 |         |          |          |
              Position 0: [A,D,G,J] → RS encode → [P0]
              Position 1: [B,E,H,K] → RS encode → [Q0]
              Position 2: [C,F,I,L] → RS encode → [R0]

    Parity:  P1[P0,Q0,R0]

    This allows byte-level recovery across the document.
    """
    from reedsolo import RSCodec

    rs = RSCodec(nsym=num_parity)
    chunk_size = len(data_chunks[0])
    parity_chunks = [bytearray() for _ in range(num_parity)]

    for byte_pos in range(chunk_size):
        # Get byte at this position from all data chunks
        data_bytes = bytearray([chunk[byte_pos] for chunk in data_chunks])

        # Encode with Reed-Solomon
        encoded = rs.encode(data_bytes)

        # Parity bytes are at the end
        parity_bytes = encoded[-num_parity:]

        # Distribute to parity chunks
        for i in range(num_parity):
            parity_chunks[i].append(parity_bytes[i])

    return [bytes(p) for p in parity_chunks]
```

### Recovery Algorithm

**Byte-by-byte recovery:**

```python
def recover_missing_chunks(all_chunks: List[Optional[bytes]],
                          parity_chunks: List[bytes],
                          num_data_chunks: int) -> List[bytes]:
    """
    Recover missing chunks using parity data.

    Args:
        all_chunks: List with None for missing chunks
        parity_chunks: List of parity chunks
        num_data_chunks: Expected number of data chunks

    Returns:
        List of recovered data chunks (no None values)

    Example:
        Input:  [D1, None, D3, D4] + [P1]  (D2 is missing)
        Output: [D1, D2_recovered, D3, D4]
    """
    from reedsolo import RSCodec

    num_parity = len(parity_chunks)
    rs = RSCodec(nsym=num_parity)

    # Find missing positions
    missing_positions = [i for i, chunk in enumerate(all_chunks[:num_data_chunks])
                        if chunk is None]

    if len(missing_positions) > num_parity:
        raise ValueError(
            f"Cannot recover: {len(missing_positions)} chunks missing "
            f"but only {num_parity} parity pages available"
        )

    if not missing_positions:
        return all_chunks[:num_data_chunks]  # Nothing to recover

    chunk_size = len(parity_chunks[0])

    # Initialize recovered chunks
    recovered_chunks = [chunk if chunk else bytearray(chunk_size)
                       for chunk in all_chunks[:num_data_chunks]]

    # Recover byte-by-byte
    for byte_pos in range(chunk_size):
        # Build byte array: data bytes + parity bytes
        data_bytes = bytearray()
        for i in range(num_data_chunks):
            if all_chunks[i] is not None:
                data_bytes.append(all_chunks[i][byte_pos])
            else:
                data_bytes.append(0)  # Placeholder

        # Add parity bytes
        for parity_chunk in parity_chunks:
            data_bytes.append(parity_chunk[byte_pos])

        # Decode with erasure positions
        decoded = rs.decode(data_bytes, erase_pos=missing_positions)

        # Update recovered chunks
        for i in missing_positions:
            recovered_chunks[i][byte_pos] = decoded[i]

    return [bytes(chunk) for chunk in recovered_chunks]
```

---

## Testing Strategy

### Unit Tests (12 tests)

**Parity Generation (4 tests):**
1. `test_calculate_parity_count` - Verify formula ceil(n/20)
2. `test_pad_chunks` - Verify all chunks padded to same size
3. `test_generate_parity_chunks` - Verify parity generation
4. `test_parity_different_counts` - Test 1, 2, 5 parity pages

**Parity Recovery (5 tests):**
5. `test_recover_single_missing` - Recover 1 missing chunk
6. `test_recover_multiple_missing` - Recover 2 missing chunks
7. `test_recover_none_missing` - No-op when all present
8. `test_too_many_missing` - Error when can't recover
9. `test_recover_last_page` - Edge case: last page missing

**Metadata Parsing (3 tests):**
10. `test_parse_data_page_with_parity_flag` - Data page with 0x00
11. `test_parse_parity_page_metadata` - Parity page with full metadata
12. `test_parity_page_structure` - Verify metadata byte layout

### Integration Tests (10 tests)

**Encode/Decode Cycle (4 tests):**
1. `test_encode_with_default_parity` - Encode with --parity
2. `test_encode_with_custom_parity` - Encode with --parity-pages 3
3. `test_decode_with_parity_all_present` - Decode when no pages missing
4. `test_decode_with_parity_recovery` - Decode and recover missing page

**Recovery Scenarios (3 tests):**
5. `test_recover_from_middle_page_missing` - Remove page 5 of 10
6. `test_recover_from_multiple_missing` - Remove 2 pages, 2 parity
7. `test_cannot_recover_too_many_missing` - Remove 3 pages, 2 parity (fail)

**Combined Features (3 tests):**
8. `test_parity_with_encryption` - Parity + encryption + recovery
9. `test_parity_with_shuffled_pages` - Parity + order-independent
10. `test_parity_mixed_document_detection` - Parity pages with wrong MD5

### Manual Tests (5 tests)

1. **Large file test** - 25KB file with parity, remove page, recover
2. **Print/scan test** - Print, scan, exclude page, recover
3. **Multiple parity test** - 5 parity pages, remove 5 pages, recover
4. **Performance test** - Encode/decode time < 15 seconds
5. **Visual test** - Verify parity page headers clear and distinct

---

## Success Criteria

### Functional Requirements

- ✅ Generate parity pages using Reed-Solomon erasure codes
- ✅ Default parity count = ceil(num_data_pages / 20)
- ✅ User can specify custom parity count with --parity-pages N
- ✅ Recover from up to N missing pages with N parity pages
- ✅ Error clearly when too many pages missing to recover
- ✅ Parity pages marked clearly in PDF headers
- ✅ Parity pages have same MD5 as data pages (document consistency)
- ✅ Works with encrypted documents (parity over ciphertext)
- ✅ Works with order-independent decoding
- ✅ Works with mixed document detection

### Performance Requirements

- ✅ < 10 seconds to encode 25KB file with parity (on modern hardware)
- ✅ < 15 seconds to decode and recover from 1-2 missing pages
- ✅ Parity overhead ≤ 10% additional pages (typical use case)

### Testing Requirements

- ✅ All 12 unit tests passing
- ✅ All 10 integration tests passing
- ✅ All 5 manual tests completed successfully
- ✅ Combined with encryption: all tests passing
- ✅ Combined with order-independence: all tests passing
- ✅ No regressions in existing tests

### Documentation Requirements

- ✅ README.md updated with parity examples
- ✅ CLAUDE.md updated with implementation details
- ✅ Binary format documented
- ✅ CLI options documented
- ✅ Recovery process explained

---

## Edge Cases & Error Handling

### Edge Cases to Handle

1. **No data pages, only parity** - Error with clear message
2. **Parity pages from different document** - Detect via MD5 mismatch
3. **All parity pages missing** - Fall back to normal validation (error on missing data)
4. **More parity pages than data pages** - Wasteful but allowed
5. **Parity page itself damaged** - May not be able to recover (need parity for parity!)
6. **Uneven chunk sizes** - Padding handles this automatically
7. **Recovery mode + parity** - Try parity first, then partial recovery
8. **Single data page document** - Still generates 1 parity page (ceil(1/20) = 1)

### Error Messages

**Too many pages missing:**
```
Error: Cannot recover from 3 missing pages with only 2 parity pages available.

Missing pages: [3, 7, 11]
Available parity: 2 pages

To recover all missing pages, you would need at least 3 parity pages.
Consider encoding with --parity-pages 3 for this level of redundancy.
```

**Parity pages from wrong document:**
```
Error: Parity page 21 belongs to a different document!

Expected MD5 (from data pages): a1b2c3d4e5f6...
Found MD5 (parity page 21):     9a8b7c6d5e4f...

This indicates pages from multiple QR code backups are mixed.
Please ensure all pages (including parity) are from the same backup.
```

**Recovery successful:**
```
Found 1 parity page
Missing 1 data page: [5]
Attempting parity recovery...
Successfully recovered 1 page!

Verification: PASS (MD5: 3f7a8b2c1d4e5f6a...)
```

---

## Dependencies

### New Dependency

```python
# requirements.txt
reedsolo>=1.7.0  # Reed-Solomon error correction for parity pages
```

**Library choice rationale:**
- Pure Python implementation (no C dependencies)
- Well-maintained (last update 2023)
- Simple API
- Supports erasure decoding (exactly what we need)
- Compatible with all platforms

---

## Backward Compatibility

### Guarantees

1. **Unencrypted, no-parity PDFs** - Continue to work exactly as before
2. **Parity flag = 0x00** - Data pages backward compatible
3. **No parity pages** - Decoder falls back to existing validation
4. **Future format versions** - Parity flag byte allows extension

### Migration Path

- Users can mix old and new PDFs
- Old decode command works with new PDFs (ignores parity if all pages present)
- New decode command works with old PDFs (detects no parity, normal flow)

---

## Performance Considerations

### Encoding Performance

**Reed-Solomon complexity:** O(n * m) where n = data chunks, m = parity chunks

**Example: 100 data pages + 5 parity pages**
- Each byte position: 100 data bytes → 5 parity bytes
- Typical chunk: ~2800 bytes
- Total operations: 100 × 5 × 2800 = 1,400,000 operations
- Expected time: < 5 seconds (modern CPU)

### Decoding Performance

**Recovery only when needed:**
- If all pages present: Zero overhead (parity not computed)
- If pages missing: O(n * m) recovery per byte position
- Expected: < 10 seconds to recover 1-2 pages from 100-page document

### Memory Usage

**Additional memory:**
- Parity chunks: ~5% of compressed data size
- Recovery buffer: Same as data size
- Expected: < 10MB additional RAM for 25KB file

---

## Implementation Notes

### Code Locations

**New functions (qr_code_backup.py):**
- `calculate_parity_count(num_data_pages, parity_pages=None)`
- `pad_chunks(chunks)`
- `generate_parity_chunks(data_chunks, num_parity)`
- `recover_missing_chunks(all_chunks, parity_chunks, num_data_chunks)`

**Modified functions:**
- `create_chunks()` - Add parity generation
- `parse_binary_chunk()` - Parse parity flag and metadata
- `reassemble_chunks()` - Add parity recovery logic
- `generate_pdf()` - Update headers for parity pages

**New test file:**
- `tests/test_parity.py` - All parity-specific tests

### Dependencies on Previous Features

**Requires:**
- ✅ Order-independent decoding (Week 1) - Parity works with shuffled pages
- ✅ Mixed document detection (Week 1) - Parity pages must match MD5
- ✅ Encryption (Weeks 2-3) - Parity computed over ciphertext

**Enables:**
- Enhanced reliability for long-term archival
- Confidence in physical backup durability
- Recovery from partial document damage

---

## Timeline Summary

| Week | Days | Focus | Deliverables |
|------|------|-------|-------------|
| 4 | 1-5 | Core parity functions | 12 unit tests, parity generation/recovery |
| 5 | 6-10 | Encode/decode integration | 10 integration tests, full encode→decode→recover |
| 6 | 11-15 | CLI, docs, final testing | CLI integration, docs, manual tests, commit |

**Total:** 15 days, 22+ tests, 4 new functions, 4 modified functions

---

## Next Steps

1. **Approve this plan** - Review and approve implementation approach
2. **Create feature branch** - `git checkout -b feature/parity-pages`
3. **Day 1: Setup** - Install reedsolo, create test skeleton
4. **Daily progress** - Implement according to plan, commit regularly
5. **Week 6: Final review** - Complete testing and documentation
6. **Commit and merge** - Merge to main after all tests pass

---

**Plan Version:** 1.0
**Created:** 2025-10-21
**Status:** Ready for implementation
**Estimated effort:** 15 days (3 weeks part-time)
