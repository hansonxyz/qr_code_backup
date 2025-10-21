# Phase 2 Features - QR Code Backup

This document describes planned enhancements to the QR Code Backup tool, including implementation details and test plans.

## Summary

Four major features are planned for Phase 2:

1. **Encryption** (Priority 1): AES-256-GCM encryption with Argon2id key derivation for secure archival
2. **Parity Pages** (Priority 2): PAR2-like Reed-Solomon parity for recovering from missing/damaged pages
3. **Order-Independent Decoding** (Priority 1): Allow pages to be scanned in any order
4. **Mixed Document Detection** (Priority 1): Immediate error when pages from different documents are detected

**Implementation order:** Features 3 & 4 first (quick wins, 1 week), then Encryption (2 weeks), then Parity (3 weeks).

---

## Feature 1: Encryption (Priority 1)

### Overview

Add optional symmetric encryption using AES-256-GCM with Argon2id key derivation. Users can encrypt files before encoding to QR codes for secure archival of sensitive data.

**Use Cases:**
- Encryption keys and certificates
- Legal documents with PII
- Password databases
- Any sensitive data requiring offline backup

### Design Decisions

**Encryption Algorithm:**
- **AES-256-GCM** (Galois/Counter Mode)
  - Authenticated encryption (prevents tampering)
  - 256-bit keys (quantum-safe against Grover's algorithm)
  - Built-in integrity verification

**Key Derivation:**
- **Argon2id** (winner of Password Hashing Competition)
  - Resistant to GPU/ASIC attacks
  - Memory-hard function
  - Configurable time/memory cost
  - Better than PBKDF2 or bcrypt

**Why NOT Elliptic Curve?**
- ECC is NOT quantum resistant (vulnerable to Shor's algorithm)
- Asymmetric crypto adds complexity without benefit for this use case
- Symmetric crypto (AES-256) is actually quantum-safe

### Pipeline Integration

**Current Pipeline:**
```
Read file → Compress (bzip2) → Chunk → QR encode
```

**With Encryption:**
```
Read file → Compress (bzip2) → Encrypt (AES-256-GCM) → Chunk → QR encode
```

**Key Point:** Encryption happens AFTER compression but BEFORE chunking.

### Binary Metadata Changes

**Current Page 1 Format:**
```
[MD5: 16 bytes][Page#: 2 bytes][FileSize: 4 bytes][Data: variable]
```

**New Page 1 Format (with encryption):**
```
[Encryption Flag: 1 byte]
[MD5: 16 bytes]
[Page#: 2 bytes]
[FileSize: 4 bytes]
[Salt: 16 bytes]              ← NEW (if encrypted)
[Argon2 Parameters: 12 bytes] ← NEW (if encrypted)
[Verification Hash: 32 bytes] ← NEW (if encrypted)
[Nonce: 12 bytes]             ← NEW (if encrypted, for AES-GCM)
[Data: variable]
```

**Encryption Flag (1 byte):**
- `0x00` = Not encrypted (current behavior)
- `0x01` = Encrypted with AES-256-GCM + Argon2id
- Future: `0x02`-`0xFF` for other encryption schemes

**Salt (16 bytes):**
- Random salt for Argon2id key derivation
- Generated during encryption
- Unique per document

**Argon2 Parameters (12 bytes):**
- Time cost (4 bytes uint32): Number of iterations
- Memory cost (4 bytes uint32): Memory in KB
- Parallelism (4 bytes uint32): Number of threads
- Default: time=3, memory=65536 (64MB), parallelism=4

**Verification Hash (32 bytes):**
- BLAKE2b hash of derived key (first 32 bytes)
- Used to verify password is correct before attempting decryption
- Avoids wasting time on wrong password

**Nonce (12 bytes):**
- Random nonce for AES-GCM
- 96 bits (recommended size for GCM)
- Generated during encryption

**Other Pages (encrypted):**
```
[Encryption Flag: 1 byte][MD5: 16 bytes][Page#: 2 bytes][Data: variable]
```

**Overhead:**
- Page 1: +73 bytes (when encrypted)
- Other pages: +1 byte (just flag)

### Command-Line Interface

**Encode with encryption:**
```bash
# Password via stdin (prompted)
qr_code_backup encode secret.txt -o backup.pdf --encrypt

# Password via stdin (piped)
echo "mypassword" | qr_code_backup encode secret.txt -o backup.pdf --encrypt

# Password from key file
qr_code_backup encode secret.txt -o backup.pdf --encrypt-key-file password.txt
```

**Decode with encryption:**
```bash
# Password via stdin (prompted if encrypted)
qr_code_backup decode backup.pdf -o recovered.txt

# Password via stdin (explicit)
echo "mypassword" | qr_code_backup decode backup.pdf -o recovered.txt --decrypt

# Password from key file
qr_code_backup decode backup.pdf -o recovered.txt --decrypt-key-file password.txt
```

**Options:**
- `--encrypt`: Enable encryption (prompt for password)
- `--encrypt-key-file <path>`: Read password from file (trimmed, no newline)
- `--decrypt`: Enable decryption (prompt for password, auto-detected if encrypted)
- `--decrypt-key-file <path>`: Read password from file
- `--argon2-time <N>`: Argon2 time cost (default: 3)
- `--argon2-memory <KB>`: Argon2 memory cost (default: 65536 = 64MB)
- `--argon2-parallelism <N>`: Argon2 parallelism (default: 4)

### Implementation Details

**Dependencies:**
```python
# Add to requirements.txt
cryptography>=41.0.0  # For AES-256-GCM
argon2-cffi>=23.1.0   # For Argon2id
```

**New Functions:**

```python
def derive_key(password: str, salt: bytes, time_cost: int,
               memory_cost: int, parallelism: int) -> bytes:
    """Derive 32-byte key from password using Argon2id.

    Args:
        password: User password (string)
        salt: 16-byte random salt
        time_cost: Number of iterations
        memory_cost: Memory in KB
        parallelism: Number of threads

    Returns:
        32-byte derived key
    """
    from argon2 import low_level

    hash_result = low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=low_level.Type.ID  # Argon2id
    )
    return hash_result


def create_verification_hash(key: bytes) -> bytes:
    """Create verification hash from derived key.

    Uses BLAKE2b for fast, secure hashing.

    Args:
        key: 32-byte derived key

    Returns:
        32-byte verification hash
    """
    import hashlib
    return hashlib.blake2b(key, digest_size=32).digest()


def verify_password(password: str, salt: bytes, verification_hash: bytes,
                   time_cost: int, memory_cost: int, parallelism: int) -> bool:
    """Verify password against stored verification hash.

    Args:
        password: User-provided password
        salt: Salt from page 1 metadata
        verification_hash: Hash from page 1 metadata
        time_cost, memory_cost, parallelism: Argon2 parameters

    Returns:
        True if password is correct
    """
    derived_key = derive_key(password, salt, time_cost, memory_cost, parallelism)
    computed_hash = create_verification_hash(derived_key)

    # Constant-time comparison to prevent timing attacks
    import hmac
    return hmac.compare_digest(computed_hash, verification_hash)


def encrypt_data(data: bytes, password: str, time_cost: int = 3,
                memory_cost: int = 65536, parallelism: int = 4) -> dict:
    """Encrypt data with AES-256-GCM.

    Args:
        data: Data to encrypt (compressed file)
        password: User password
        time_cost, memory_cost, parallelism: Argon2 parameters

    Returns:
        Dictionary with encryption metadata and ciphertext
    """
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Generate random salt and nonce
    salt = os.urandom(16)
    nonce = os.urandom(12)  # 96 bits for GCM

    # Derive key from password
    key = derive_key(password, salt, time_cost, memory_cost, parallelism)

    # Create verification hash
    verification_hash = create_verification_hash(key)

    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)  # No additional data

    return {
        'salt': salt,
        'nonce': nonce,
        'verification_hash': verification_hash,
        'time_cost': time_cost,
        'memory_cost': memory_cost,
        'parallelism': parallelism,
        'ciphertext': ciphertext,
    }


def decrypt_data(ciphertext: bytes, password: str, salt: bytes, nonce: bytes,
                verification_hash: bytes, time_cost: int, memory_cost: int,
                parallelism: int) -> bytes:
    """Decrypt data with AES-256-GCM.

    Args:
        ciphertext: Encrypted data
        password: User password
        salt, nonce: Encryption metadata
        verification_hash: For password verification
        time_cost, memory_cost, parallelism: Argon2 parameters

    Returns:
        Decrypted data

    Raises:
        ValueError: If password is incorrect
        cryptography.exceptions.InvalidTag: If data is corrupted/tampered
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Verify password first (fast check)
    if not verify_password(password, salt, verification_hash,
                          time_cost, memory_cost, parallelism):
        raise ValueError("Incorrect password")

    # Derive key
    key = derive_key(password, salt, time_cost, memory_cost, parallelism)

    # Decrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext


def read_password(key_file: Optional[str] = None) -> str:
    """Read password from key file or stdin.

    Args:
        key_file: Path to key file, or None to prompt stdin

    Returns:
        Password string (stripped of whitespace)
    """
    import click

    if key_file:
        with open(key_file, 'r') as f:
            return f.read().strip()
    else:
        return click.prompt('Enter password', hide_input=True).strip()
```

**Modifications to Existing Functions:**

```python
def create_chunks(file_path: str, chunk_size: int, compression: str = 'bzip2',
                 encrypt: bool = False, password: Optional[str] = None,
                 **argon2_params) -> Tuple[List[bytes], dict]:
    """Modified to support encryption.

    Returns:
        Tuple of (chunks, metadata_dict)
        metadata_dict includes encryption params if encrypted
    """
    # ... compress data ...

    if encrypt:
        if password is None:
            raise ValueError("Password required for encryption")

        enc_result = encrypt_data(data_to_chunk, password, **argon2_params)
        data_to_chunk = enc_result['ciphertext']
        encryption_metadata = {
            'encrypted': True,
            'salt': enc_result['salt'],
            'nonce': enc_result['nonce'],
            'verification_hash': enc_result['verification_hash'],
            'time_cost': enc_result['time_cost'],
            'memory_cost': enc_result['memory_cost'],
            'parallelism': enc_result['parallelism'],
        }
    else:
        encryption_metadata = {'encrypted': False}

    # Calculate MD5 of (possibly encrypted) compressed data
    file_md5 = hashlib.md5(data_to_chunk).digest()

    # ... create chunks ...

    # Build page 1 chunk with encryption metadata
    if page_num == 1:
        chunk_binary = bytearray()
        chunk_binary.append(0x01 if encrypt else 0x00)  # Encryption flag
        chunk_binary.extend(file_md5)
        chunk_binary.extend(page_num.to_bytes(2, 'big'))
        chunk_binary.extend(file_size.to_bytes(4, 'big'))

        if encrypt:
            chunk_binary.extend(encryption_metadata['salt'])
            chunk_binary.extend(encryption_metadata['time_cost'].to_bytes(4, 'big'))
            chunk_binary.extend(encryption_metadata['memory_cost'].to_bytes(4, 'big'))
            chunk_binary.extend(encryption_metadata['parallelism'].to_bytes(4, 'big'))
            chunk_binary.extend(encryption_metadata['verification_hash'])
            chunk_binary.extend(encryption_metadata['nonce'])

        chunk_binary.extend(chunk_data)

    return chunks, encryption_metadata


def parse_binary_chunk(chunk_binary: bytes) -> Optional[Dict[str, Any]]:
    """Modified to parse encryption metadata."""
    try:
        # Read encryption flag
        encrypted = chunk_binary[0] != 0x00
        offset = 1

        # Read MD5
        md5_hash = chunk_binary[offset:offset+16]
        offset += 16

        # Read page number
        page_num = int.from_bytes(chunk_binary[offset:offset+2], 'big')
        offset += 2

        result = {
            'encrypted': encrypted,
            'md5_hash': md5_hash,
            'page_number': page_num,
        }

        # Page 1 has file size (and possibly encryption metadata)
        if page_num == 1:
            file_size = int.from_bytes(chunk_binary[offset:offset+4], 'big')
            offset += 4
            result['file_size'] = file_size

            if encrypted:
                # Read encryption metadata
                result['salt'] = chunk_binary[offset:offset+16]
                offset += 16
                result['time_cost'] = int.from_bytes(chunk_binary[offset:offset+4], 'big')
                offset += 4
                result['memory_cost'] = int.from_bytes(chunk_binary[offset:offset+4], 'big')
                offset += 4
                result['parallelism'] = int.from_bytes(chunk_binary[offset:offset+4], 'big')
                offset += 4
                result['verification_hash'] = chunk_binary[offset:offset+32]
                offset += 32
                result['nonce'] = chunk_binary[offset:offset+12]
                offset += 12

        # Data is everything after metadata
        result['data'] = chunk_binary[offset:]

        return result
    except Exception:
        return None


def reassemble_chunks(chunk_binaries: List[bytes], verify: bool = True,
                     recovery_mode: bool = False,
                     password: Optional[str] = None) -> Tuple[bytes, Dict[str, Any]]:
    """Modified to support decryption."""
    # ... parse chunks, validate ...

    # Reassemble compressed (possibly encrypted) data
    compressed_data = b''.join([chunk['data'] for chunk in parsed_chunks])

    # Check if encrypted
    if page_1.get('encrypted'):
        if password is None:
            raise ValueError("Document is encrypted but no password provided")

        # Decrypt
        try:
            click.echo("Decrypting...")
            compressed_data = decrypt_data(
                compressed_data,
                password,
                page_1['salt'],
                page_1['nonce'],
                page_1['verification_hash'],
                page_1['time_cost'],
                page_1['memory_cost'],
                page_1['parallelism']
            )
            report['decryption'] = 'success'
        except ValueError as e:
            raise ValueError(f"Decryption failed: {e}")
        except Exception as e:
            raise ValueError(f"Decryption failed - data may be corrupted: {e}")

    # Verify MD5 of decrypted compressed data
    actual_md5 = hashlib.md5(compressed_data).digest()
    if actual_md5 != reference_md5:
        raise ValueError("MD5 verification failed after decryption")

    # Decompress
    file_data = decompress_data(compressed_data, 'bzip2')

    # ... return ...
```

### Security Considerations

**Password Strength:**
- Recommend minimum 12 characters
- Display warning for weak passwords
- No maximum length (Argon2id handles long passwords)

**Argon2 Parameters:**
- Default (time=3, memory=64MB, parallelism=4) provides ~0.5-1 second derivation time
- Configurable for users who want stronger (slower) or weaker (faster) KDF
- Memory cost prevents GPU attacks

**Verification Hash:**
- Fast password check without attempting full decryption
- Prevents timing attacks (constant-time comparison)
- Uses BLAKE2b (faster than SHA-256, equally secure)

**AES-GCM:**
- Authenticated encryption prevents tampering
- If data is modified, decryption will fail with InvalidTag exception
- Nonce must be unique per encryption (ensured by random generation)

**Salt and Nonce:**
- Both use cryptographically secure random (os.urandom)
- Salt prevents rainbow table attacks on password
- Nonce prevents IV reuse attacks

### Test Plan

#### Unit Tests

**Test 1: Key Derivation**
```python
def test_key_derivation():
    """Test Argon2id key derivation is deterministic."""
    password = "test_password_123"
    salt = b"1234567890123456"  # 16 bytes

    key1 = derive_key(password, salt, 3, 65536, 4)
    key2 = derive_key(password, salt, 3, 65536, 4)

    assert key1 == key2  # Same inputs = same key
    assert len(key1) == 32  # 256 bits
```

**Test 2: Verification Hash**
```python
def test_verification_hash():
    """Test password verification."""
    password = "correct_password"
    wrong_password = "wrong_password"
    salt = os.urandom(16)

    key = derive_key(password, salt, 3, 65536, 4)
    verification_hash = create_verification_hash(key)

    # Correct password
    assert verify_password(password, salt, verification_hash, 3, 65536, 4)

    # Wrong password
    assert not verify_password(wrong_password, salt, verification_hash, 3, 65536, 4)
```

**Test 3: Encryption/Decryption**
```python
def test_encryption_decryption():
    """Test AES-256-GCM encryption round-trip."""
    data = b"This is secret data" * 1000
    password = "secure_password_123"

    # Encrypt
    enc_result = encrypt_data(data, password)

    # Decrypt with correct password
    decrypted = decrypt_data(
        enc_result['ciphertext'],
        password,
        enc_result['salt'],
        enc_result['nonce'],
        enc_result['verification_hash'],
        enc_result['time_cost'],
        enc_result['memory_cost'],
        enc_result['parallelism']
    )

    assert decrypted == data
```

**Test 4: Wrong Password**
```python
def test_wrong_password():
    """Test decryption fails with wrong password."""
    data = b"Secret data"
    password = "correct"
    wrong = "incorrect"

    enc_result = encrypt_data(data, password)

    with pytest.raises(ValueError, match="Incorrect password"):
        decrypt_data(
            enc_result['ciphertext'],
            wrong,  # Wrong password
            enc_result['salt'],
            enc_result['nonce'],
            enc_result['verification_hash'],
            enc_result['time_cost'],
            enc_result['memory_cost'],
            enc_result['parallelism']
        )
```

**Test 5: Tampered Data**
```python
def test_tampered_data():
    """Test decryption fails if ciphertext is modified."""
    data = b"Secret data"
    password = "password123"

    enc_result = encrypt_data(data, password)

    # Tamper with ciphertext
    tampered = bytearray(enc_result['ciphertext'])
    tampered[10] ^= 0xFF  # Flip some bits

    with pytest.raises(Exception):  # InvalidTag from cryptography
        decrypt_data(
            bytes(tampered),
            password,
            enc_result['salt'],
            enc_result['nonce'],
            enc_result['verification_hash'],
            enc_result['time_cost'],
            enc_result['memory_cost'],
            enc_result['parallelism']
        )
```

#### Integration Tests

**Test 6: Encrypted Encode/Decode**
```python
def test_encrypted_encode_decode():
    """Test full encrypted encode-decode cycle."""
    # Create test file
    test_data = b"Sensitive information" * 100
    with open('test_encrypted.bin', 'wb') as f:
        f.write(test_data)

    password = "encryption_password_123"

    # Encode with encryption
    encode_cmd(
        input_file='test_encrypted.bin',
        output='encrypted.pdf',
        encrypt=True,
        password=password
    )

    # Decode with password
    decode_cmd(
        input_pdf='encrypted.pdf',
        output='recovered_encrypted.bin',
        password=password
    )

    # Verify
    with open('recovered_encrypted.bin', 'rb') as f:
        recovered = f.read()

    assert recovered == test_data
```

**Test 7: Encrypted PDF Without Password**
```python
def test_encrypted_pdf_without_password():
    """Test decoding encrypted PDF without password fails."""
    # ... encode with password ...

    with pytest.raises(ValueError, match="encrypted but no password"):
        decode_cmd(
            input_pdf='encrypted.pdf',
            output='output.bin',
            password=None  # No password provided
        )
```

**Test 8: Key File Support**
```python
def test_key_file():
    """Test encryption/decryption with key file."""
    with open('keyfile.txt', 'w') as f:
        f.write('my_secure_password\n')  # With newline

    # Encode with key file
    encode_cmd(
        input_file='data.bin',
        output='encrypted.pdf',
        encrypt_key_file='keyfile.txt'
    )

    # Decode with key file
    decode_cmd(
        input_pdf='encrypted.pdf',
        output='recovered.bin',
        decrypt_key_file='keyfile.txt'
    )

    # Verify files match
```

**Test 9: Different Argon2 Parameters**
```python
def test_custom_argon2_params():
    """Test encryption with custom Argon2 parameters."""
    password = "password"

    # Encode with custom params
    encode_cmd(
        input_file='data.bin',
        output='encrypted.pdf',
        encrypt=True,
        password=password,
        argon2_time=5,
        argon2_memory=131072,  # 128MB
        argon2_parallelism=8
    )

    # Decode should work (params stored in metadata)
    decode_cmd(
        input_pdf='encrypted.pdf',
        output='recovered.bin',
        password=password
    )
```

#### Manual Tests

**Test 10: Large File Encryption**
- Encode 25KB file with encryption
- Verify PDF pages look correct
- Decode and verify
- Check performance (should be < 5 seconds total)

**Test 11: Special Characters in Password**
- Test passwords with: unicode, spaces, special chars
- Ensure all work correctly

**Test 12: Very Long Password**
- Test with 100+ character password
- Verify Argon2id handles it correctly

**Test 13: Key File with Trailing Newline**
- Create key file with newline
- Verify it's properly stripped during read

### Edge Cases

1. **Empty password**: Error with clear message
2. **Very weak password**: Display warning, allow if user confirms
3. **Encrypted + Recovery mode**: Still require password
4. **Mixed encrypted/unencrypted pages**: Detect and error (MD5 would differ anyway)
5. **Wrong Argon2 params in keyfile**: Should still work (params in PDF metadata)
6. **File size after encryption**: Account for GCM auth tag (16 bytes overhead)

### Documentation Updates

**Files to update:**
- `README.md`: Add encryption examples
- `CLAUDE.md`: Document encryption architecture
- `QR_CODE_BACKUP.md`: Update data format section
- CLI help text: Document encryption options

### Success Criteria

- ✅ Encrypt/decrypt files with password
- ✅ Support key files
- ✅ Argon2id KDF with configurable parameters
- ✅ AES-256-GCM authenticated encryption
- ✅ Fast password verification before decryption
- ✅ Clear error messages for wrong password
- ✅ Detect tampered encrypted data
- ✅ < 2 seconds encryption/decryption for 25KB file
- ✅ All unit tests pass
- ✅ All integration tests pass
- ✅ Documentation complete

---

## Feature 2: Parity Pages (Priority 2)

### Overview

Add PAR2-like parity pages using Reed-Solomon error correction to enable recovery from missing or damaged pages. This provides redundancy at the document level, allowing reconstruction of lost data pages using parity pages.

**Use Cases:**
- Long-term archival where physical degradation is expected
- Large documents where losing a few pages is likely
- Critical data requiring maximum redundancy

### Design Decisions

**Parity Algorithm:**
- **Reed-Solomon** erasure codes
- Can recover from up to N missing pages if N parity pages exist
- Works at byte level on data chunks

**Default Parity Count:**
- Formula: `ceil(num_data_pages / 20)`
- Examples:
  - 1-20 pages → 1 parity page (5% overhead)
  - 21-40 pages → 2 parity pages
  - 100 pages → 5 parity pages
- User configurable via `--parity-pages N`

**Parity Page Placement:**
- Placed at END of document
- Clearly marked in header as "PARITY PAGE"
- Page numbers continue sequence (e.g., 20 data pages + 1 parity = pages 1-21)

### Pipeline Integration

**Current Pipeline:**
```
Read → Compress → [Encrypt] → Chunk → QR encode → PDF
```

**With Parity:**
```
Read → Compress → [Encrypt] → Chunk → Generate Parity → QR encode → PDF
                                         ↓
                                   Data pages + Parity pages
```

**Key Point:** Parity is computed AFTER chunking, before QR encoding.

### Binary Metadata Changes

**Parity Page Format:**
```
[Encryption Flag: 1 byte]
[MD5: 16 bytes]           ← Same MD5 as data pages
[Page#: 2 bytes]          ← Continues sequence (e.g., page 21 of 21)
[Parity Flag: 1 byte]     ← NEW: 0x01 for parity page
[Parity Index: 2 bytes]   ← NEW: Which parity page (0-indexed)
[Total Parity: 2 bytes]   ← NEW: Total number of parity pages
[Total Data: 2 bytes]     ← NEW: Total number of data pages
[Parity Data: variable]   ← Reed-Solomon encoded parity bytes
```

**Data Page Update:**
```
[Encryption Flag: 1 byte]
[MD5: 16 bytes]
[Page#: 2 bytes]
[Parity Flag: 1 byte]     ← NEW: 0x00 for data page
[FileSize: 4 bytes]       ← Only on page 1
[Encryption metadata...]  ← Only if encrypted
[Data: variable]
```

**Overhead:**
- Data pages: +1 byte (parity flag)
- Parity pages: +9 bytes metadata
- Total document: +N parity pages (N = ceil(data_pages / 20))

### Reed-Solomon Implementation

**Library:**
```python
# Add to requirements.txt
reedsolo>=1.7.0  # Reed-Solomon error correction
```

**How it works:**
1. Treat each data page's chunk as a "symbol"
2. Pad all chunks to same size (use max chunk size)
3. Generate parity "symbols" using Reed-Solomon
4. Store parity symbols in parity pages

**Example (10 data pages, 1 parity page):**
```python
from reedsolo import RSCodec

# Create codec that can recover 1 erasure
rs = RSCodec(nsym=1)  # 1 parity symbol

# Encode (input: 10 data chunks, output: 10 data + 1 parity)
data_chunks = [chunk1, chunk2, ..., chunk10]  # All same size
parity_data = rs.encode(b''.join(data_chunks))

# Parity chunk is the last N bytes
parity_chunk = parity_data[-len(chunk1):]
```

**Recovery (missing page 5):**
```python
# Mark missing page as erasure
received = [chunk1, chunk2, chunk3, chunk4, None, chunk6, ..., chunk10, parity_chunk]

# Reconstruct
recovered = rs.decode(received, erase_pos=[4])  # Position 4 is missing
```

### Command-Line Interface

**Encode with parity:**
```bash
# Default parity (ceil(pages / 20))
qr_code_backup encode data.bin -o backup.pdf --parity

# Custom parity count
qr_code_backup encode data.bin -o backup.pdf --parity-pages 3

# Parity + encryption
qr_code_backup encode data.bin -o backup.pdf --parity --encrypt
```

**Decode with parity recovery:**
```bash
# Automatic parity detection and recovery
qr_code_backup decode backup.pdf -o recovered.bin

# Explicit recovery mode (tries harder)
qr_code_backup decode backup.pdf -o recovered.bin --recovery-mode
```

**Options:**
- `--parity`: Enable parity pages (default count)
- `--parity-pages N`: Generate N parity pages
- `--no-parity`: Disable parity (default)

**Info command update:**
```bash
qr_code_backup info backup.pdf

# Output includes:
# Data pages: 20
# Parity pages: 1
# Can recover from: 1 missing page(s)
```

### Implementation Details

**New Functions:**

```python
def calculate_parity_count(num_data_pages: int,
                          parity_pages: Optional[int] = None) -> int:
    """Calculate number of parity pages.

    Args:
        num_data_pages: Number of data pages
        parity_pages: User-specified count, or None for auto

    Returns:
        Number of parity pages to generate
    """
    if parity_pages is not None:
        return parity_pages

    # Default: ceil(num_data_pages / 20)
    import math
    return math.ceil(num_data_pages / 20)


def pad_chunks(chunks: List[bytes]) -> Tuple[List[bytes], int]:
    """Pad all chunks to same size (required for Reed-Solomon).

    Args:
        chunks: List of variable-size chunks

    Returns:
        Tuple of (padded_chunks, original_max_size)
    """
    max_size = max(len(chunk) for chunk in chunks)

    padded = []
    for chunk in chunks:
        if len(chunk) < max_size:
            # Pad with zeros
            padded.append(chunk + b'\x00' * (max_size - len(chunk)))
        else:
            padded.append(chunk)

    return padded, max_size


def generate_parity_chunks(data_chunks: List[bytes],
                          num_parity: int) -> List[bytes]:
    """Generate parity chunks using Reed-Solomon.

    Args:
        data_chunks: List of data chunks (must be same size)
        num_parity: Number of parity chunks to generate

    Returns:
        List of parity chunks
    """
    from reedsolo import RSCodec

    # Create Reed-Solomon codec
    rs = RSCodec(nsym=num_parity)

    chunk_size = len(data_chunks[0])

    # Encode each byte position across all chunks
    # This creates "vertical" parity across the document
    parity_chunks = [bytearray() for _ in range(num_parity)]

    for byte_pos in range(chunk_size):
        # Get byte at position from all data chunks
        data_bytes = bytearray([chunk[byte_pos] for chunk in data_chunks])

        # Encode with Reed-Solomon
        encoded = rs.encode(data_bytes)

        # Parity bytes are at the end
        parity_bytes = encoded[-num_parity:]

        # Distribute to parity chunks
        for i in range(num_parity):
            parity_chunks[i].append(parity_bytes[i])

    return [bytes(p) for p in parity_chunks]


def recover_missing_chunks(all_chunks: List[Optional[bytes]],
                          parity_chunks: List[bytes],
                          num_data_chunks: int) -> List[bytes]:
    """Recover missing chunks using parity data.

    Args:
        all_chunks: List with None for missing chunks
        parity_chunks: List of parity chunks
        num_data_chunks: Expected number of data chunks

    Returns:
        List of recovered data chunks

    Raises:
        ValueError: If too many chunks missing to recover
    """
    from reedsolo import RSCodec

    num_parity = len(parity_chunks)
    rs = RSCodec(nsym=num_parity)

    # Find missing positions
    missing_positions = [i for i, chunk in enumerate(all_chunks)
                        if chunk is None]

    if len(missing_positions) > num_parity:
        raise ValueError(
            f"Cannot recover: {len(missing_positions)} chunks missing "
            f"but only {num_parity} parity pages available"
        )

    if not missing_positions:
        # Nothing missing
        return all_chunks[:num_data_chunks]

    chunk_size = len(parity_chunks[0])

    # Recover byte-by-byte
    recovered_chunks = [chunk if chunk else bytearray(chunk_size)
                       for chunk in all_chunks[:num_data_chunks]]

    for byte_pos in range(chunk_size):
        # Get byte from available data chunks and parity chunks
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
        try:
            decoded = rs.decode(data_bytes, erase_pos=missing_positions)

            # Update recovered chunks
            for i in missing_positions:
                recovered_chunks[i][byte_pos] = decoded[i]
        except Exception as e:
            raise ValueError(f"Parity recovery failed at byte {byte_pos}: {e}")

    return [bytes(chunk) for chunk in recovered_chunks]
```

**Modifications to create_chunks():**

```python
def create_chunks(..., parity_pages: Optional[int] = None) -> Tuple[List[bytes], dict]:
    """Modified to optionally generate parity chunks.

    Returns:
        Tuple of (all_chunks, metadata)
        all_chunks includes data chunks + parity chunks
    """
    # ... existing chunk creation ...

    data_chunks = chunks  # Save data chunks

    if parity_pages is not None or parity_pages > 0:
        num_parity = calculate_parity_count(len(data_chunks), parity_pages)

        # Pad chunks to same size
        padded_data, max_size = pad_chunks(data_chunks)

        # Generate parity
        click.echo(f"Generating {num_parity} parity page(s)...")
        parity_chunks_data = generate_parity_chunks(padded_data, num_parity)

        # Build parity chunks with metadata
        for parity_idx, parity_data in enumerate(parity_chunks_data):
            page_num = len(data_chunks) + parity_idx + 1

            chunk_binary = bytearray()
            chunk_binary.append(encryption_flag)
            chunk_binary.extend(file_md5)
            chunk_binary.extend(page_num.to_bytes(2, 'big'))
            chunk_binary.append(0x01)  # Parity flag
            chunk_binary.extend(parity_idx.to_bytes(2, 'big'))
            chunk_binary.extend(num_parity.to_bytes(2, 'big'))
            chunk_binary.extend(len(data_chunks).to_bytes(2, 'big'))
            chunk_binary.extend(parity_data)

            chunks.append(bytes(chunk_binary))

        metadata['parity_pages'] = num_parity
        metadata['total_pages'] = len(chunks)

    return chunks, metadata
```

**Modifications to parse_binary_chunk():**

```python
def parse_binary_chunk(chunk_binary: bytes) -> Optional[Dict[str, Any]]:
    """Modified to parse parity flag."""
    # ... existing parsing ...

    # Read parity flag (after page number)
    is_parity = chunk_binary[offset] != 0x00
    offset += 1
    result['is_parity'] = is_parity

    if is_parity:
        # Parse parity metadata
        result['parity_index'] = int.from_bytes(chunk_binary[offset:offset+2], 'big')
        offset += 2
        result['total_parity'] = int.from_bytes(chunk_binary[offset:offset+2], 'big')
        offset += 2
        result['total_data'] = int.from_bytes(chunk_binary[offset:offset+2], 'big')
        offset += 2

    result['data'] = chunk_binary[offset:]
    return result
```

**Modifications to reassemble_chunks():**

```python
def reassemble_chunks(chunk_binaries: List[bytes], verify: bool = True,
                     recovery_mode: bool = False,
                     password: Optional[str] = None) -> Tuple[bytes, Dict[str, Any]]:
    """Modified to support parity recovery."""
    # ... parse all chunks ...

    # Separate data and parity chunks
    data_chunks = [c for c in parsed_chunks if not c.get('is_parity')]
    parity_chunks = [c for c in parsed_chunks if c.get('is_parity')]

    if parity_chunks:
        click.echo(f"Found {len(parity_chunks)} parity page(s)")

        # Check if we have missing data pages
        data_page_numbers = [c['page_number'] for c in data_chunks]
        expected_data_pages = parity_chunks[0].get('total_data')

        missing_pages = []
        for page_num in range(1, expected_data_pages + 1):
            if page_num not in data_page_numbers:
                missing_pages.append(page_num)

        if missing_pages:
            click.echo(f"Missing {len(missing_pages)} data page(s): {missing_pages}")
            click.echo("Attempting parity recovery...")

            # Build list with None for missing
            all_data = [None] * expected_data_pages
            for chunk in data_chunks:
                all_data[chunk['page_number'] - 1] = chunk['data']

            # Extract parity data
            parity_data = [c['data'] for c in sorted(parity_chunks,
                                                     key=lambda x: x['parity_index'])]

            # Recover
            try:
                recovered = recover_missing_chunks(all_data, parity_data,
                                                  expected_data_pages)

                # Reassemble from recovered
                compressed_data = b''.join(recovered)
                click.echo(f"Successfully recovered {len(missing_pages)} page(s)!")
                report['parity_recovery'] = len(missing_pages)
            except ValueError as e:
                if not recovery_mode:
                    raise
                click.echo(f"Warning: Parity recovery failed: {e}", err=True)
        else:
            click.echo("No missing pages, parity recovery not needed")
    else:
        # No parity pages, existing behavior
        if verify and missing_pages:
            raise ValueError(f"Missing pages and no parity available: {missing_pages}")

    # ... continue with decryption/decompression ...
```

### Decode Flow Changes

**Current flow (errors immediately on missing page):**
```
Read PDF → Decode QR codes → Validate sequence → ERROR if missing
```

**New flow (defers validation until after parity check):**
```
Read PDF → Decode QR codes → Separate data/parity
                                    ↓
                          Check for missing pages
                                    ↓
                              YES           NO
                               ↓             ↓
                      Parity recovery    Assemble normally
                               ↓             ↓
                          Validate → Decrypt → Decompress
```

**Key changes:**
1. Don't error on missing pages if parity exists
2. Collect ALL pages before deciding what to do
3. Attempt parity recovery if pages missing
4. Validate MD5 AFTER recovery (recovered data must match hash)

### PDF Header Updates

**Parity page headers:**
```
┌─────────────────────────────────────────────┐
│ QR Code Backup Archive                      │
│ Title: [filename]                           │
│ Page 21 of 21 - PARITY PAGE 1 of 1         │  ← NEW
│ Decode with: qr_code_backup decode          │
└─────────────────────────────────────────────┘
```

### Test Plan

#### Unit Tests

**Test 1: Parity Count Calculation**
```python
def test_parity_count():
    assert calculate_parity_count(1) == 1      # ceil(1/20) = 1
    assert calculate_parity_count(20) == 1     # ceil(20/20) = 1
    assert calculate_parity_count(21) == 2     # ceil(21/20) = 2
    assert calculate_parity_count(100) == 5    # ceil(100/20) = 5
    assert calculate_parity_count(10, parity_pages=3) == 3  # Override
```

**Test 2: Chunk Padding**
```python
def test_chunk_padding():
    chunks = [b"abc", b"abcde", b"a"]
    padded, max_size = pad_chunks(chunks)

    assert max_size == 5
    assert len(padded[0]) == 5
    assert len(padded[1]) == 5
    assert len(padded[2]) == 5
    assert padded[0] == b"abc\x00\x00"
    assert padded[1] == b"abcde"
```

**Test 3: Parity Generation**
```python
def test_parity_generation():
    # Create 10 chunks of same size
    data = [b"chunk_%02d_data" % i for i in range(10)]

    parity = generate_parity_chunks(data, num_parity=2)

    assert len(parity) == 2
    assert len(parity[0]) == len(data[0])
```

**Test 4: Single Missing Chunk Recovery**
```python
def test_recover_single_chunk():
    # Create data
    data = [b"AAAA", b"BBBB", b"CCCC", b"DDDD"]

    # Generate parity
    parity = generate_parity_chunks(data, num_parity=1)

    # Simulate missing chunk 2 (b"CCCC")
    incomplete = [b"AAAA", b"BBBB", None, b"DDDD"]

    # Recover
    recovered = recover_missing_chunks(incomplete, parity, num_data_chunks=4)

    assert recovered[2] == b"CCCC"
    assert recovered == data
```

**Test 5: Multiple Missing Chunks**
```python
def test_recover_multiple_chunks():
    data = [b"AA", b"BB", b"CC", b"DD", b"EE"]
    parity = generate_parity_chunks(data, num_parity=2)

    # Missing 2 chunks
    incomplete = [b"AA", None, b"CC", None, b"EE"]

    recovered = recover_missing_chunks(incomplete, parity, num_data_chunks=5)

    assert recovered[1] == b"BB"
    assert recovered[3] == b"DD"
```

**Test 6: Too Many Missing**
```python
def test_too_many_missing():
    data = [b"AA", b"BB", b"CC", b"DD"]
    parity = generate_parity_chunks(data, num_parity=1)

    # Missing 2 chunks, but only 1 parity
    incomplete = [b"AA", None, None, b"DD"]

    with pytest.raises(ValueError, match="Cannot recover"):
        recover_missing_chunks(incomplete, parity, num_data_chunks=4)
```

#### Integration Tests

**Test 7: Encode with Parity**
```python
def test_encode_with_parity():
    # 5KB file should create ~19 data pages
    # ceil(19/20) = 1 parity page

    encode_cmd(
        input_file='tests/test_data/random_5kb.bin',
        output='parity_test.pdf',
        parity=True
    )

    # Verify PDF has extra page
    # Should have 5 pages data + 1 parity = 6 pages total
```

**Test 8: Decode with All Pages**
```python
def test_decode_with_parity_all_pages():
    # Encode with parity
    encode_cmd('data.bin', 'parity.pdf', parity=True)

    # Decode (all pages present)
    decode_cmd('parity.pdf', 'recovered.bin')

    # Should report parity not needed
    assert files_identical('data.bin', 'recovered.bin')
```

**Test 9: Decode with Missing Page (Recovery)**
```python
def test_decode_missing_page_with_parity():
    # Encode with parity
    encode_cmd('data.bin', 'parity.pdf', parity=True)

    # Manually remove page 3 from PDF
    remove_page_from_pdf('parity.pdf', page=3)

    # Decode (should recover)
    result = decode_cmd('parity.pdf', 'recovered.bin')

    assert "Successfully recovered 1 page(s)" in result.output
    assert files_identical('data.bin', 'recovered.bin')
```

**Test 10: Decode with Too Many Missing**
```python
def test_decode_too_many_missing():
    # Encode with 1 parity page
    encode_cmd('data.bin', 'parity.pdf', parity_pages=1)

    # Remove 2 pages
    remove_page_from_pdf('parity.pdf', pages=[3, 5])

    with pytest.raises(ValueError, match="Cannot recover"):
        decode_cmd('parity.pdf', 'recovered.bin')
```

**Test 11: Parity + Encryption**
```python
def test_parity_with_encryption():
    password = "test123"

    # Encode encrypted with parity
    encode_cmd(
        input_file='data.bin',
        output='encrypted_parity.pdf',
        encrypt=True,
        password=password,
        parity=True
    )

    # Remove a page
    remove_page_from_pdf('encrypted_parity.pdf', page=2)

    # Decode (recover + decrypt)
    decode_cmd(
        input_pdf='encrypted_parity.pdf',
        output='recovered.bin',
        password=password
    )

    assert files_identical('data.bin', 'recovered.bin')
```

**Test 12: Custom Parity Count**
```python
def test_custom_parity_count():
    # 10 page file, request 3 parity pages
    encode_cmd('data.bin', 'parity.pdf', parity_pages=3)

    # Should be able to recover from up to 3 missing
    remove_page_from_pdf('parity.pdf', pages=[2, 5, 8])

    decode_cmd('parity.pdf', 'recovered.bin')
    assert files_identical('data.bin', 'recovered.bin')
```

#### Manual Tests

**Test 13: Large File with Parity**
- Encode 25KB file with parity
- Should create ~1 parity page (ceil(20/20) = 1)
- Remove middle page
- Verify recovery works

**Test 14: Print/Scan with Parity**
- Encode file with parity
- Print on paper
- Scan back
- Intentionally exclude one page from scan
- Verify recovery from scanned PDF

### Edge Cases

1. **No data pages, only parity**: Error clearly
2. **Parity pages with wrong MD5**: Error (different file)
3. **Parity pages from different document mixed in**: Detect via MD5
4. **Uneven chunk sizes**: Padding handles this
5. **Parity page damaged**: May not be able to recover (need parity for parity!)
6. **All parity pages missing**: Falls back to normal validation (error on missing data)
7. **More parity pages than data pages**: Wasteful but allowed
8. **Recovery mode + parity**: Try parity first, then partial recovery

### Performance Considerations

**Encoding:**
- Reed-Solomon encoding is O(n*m) where n=data_chunks, m=parity_chunks
- For 100 pages + 5 parity: ~500 operations per byte position
- Expected: < 5 seconds for 25KB file

**Decoding:**
- Only computed if pages are missing
- Recovery is O(n*m) as well
- Expected: < 10 seconds for recovering 1-2 pages

### Documentation Updates

**Files to update:**
- `README.md`: Add parity examples
- `CLAUDE.md`: Document parity architecture
- `QR_CODE_BACKUP.md`: Update with parity information
- CLI help: Document parity options

### Success Criteria

- ✅ Generate parity pages (default count = ceil(pages/20))
- ✅ Parity pages clearly marked in PDF
- ✅ Recover from N missing pages with N parity pages
- ✅ Error clearly if too many pages missing
- ✅ Works with encryption
- ✅ Works with recovery mode
- ✅ Parity pages have same MD5 as data pages
- ✅ < 10 seconds encoding with parity for 25KB file
- ✅ < 15 seconds decoding with recovery for 25KB file
- ✅ All unit tests pass
- ✅ All integration tests pass
- ✅ Manual print/scan test with recovery passes

---

## Feature 3: Order-Independent Page Decoding (Priority 1)

### Overview

Allow PDF pages to be scanned/decoded in any order. The decoder should handle pages being out of sequence (e.g., if user drops printed pages and picks them up in wrong order, or scans pages in random order).

**Use Cases:**
- User accidentally shuffles printed pages
- Scanner feeds pages in reverse order
- Multiple people scanning different pages simultaneously
- Pages from different stacks get mixed together (but from same document)

### Current Behavior (Already Partially Implemented)

The current `reassemble_chunks()` function already sorts chunks by page number, not by the order they appear in the PDF:

```python
# Sort by page number
chunks_sorted = sorted(chunks, key=lambda x: x['page_number'])
```

However, we should make this more explicit and robust.

### Design Decisions

**Decoding Strategy:**
1. Decode ALL pages first (don't assume any order)
2. Parse metadata from each chunk
3. Sort chunks by page number (stored in metadata)
4. Validate sequence is complete (1, 2, 3, ... N)
5. Reassemble in correct order

**Key Point:** Physical order in PDF is irrelevant. Page metadata determines assembly order.

### Implementation Details

**Current decode flow is already order-independent:**
```python
# In decode command
for page_idx, image in enumerate(images):
    chunk_binaries = decode_qr_codes_from_image(image)
    all_chunk_binaries.append(chunk_binary)  # Order doesn't matter

# In reassemble_chunks
parsed_chunks.sort(key=lambda x: x['page_number'])  # Sort by metadata, not scan order
```

**What we need to add:**
- Explicit documentation that order doesn't matter
- Test cases for out-of-order pages
- User feedback showing "Detected pages X, Y, Z... reordering..."

**Modifications to decode command:**

```python
@cli.command()
def decode(input_pdf, output, verify, recovery_mode, force):
    """Decode with explicit order-independence."""

    click.echo("Reading QR codes...")
    all_chunk_binaries = []

    # Decode all pages without assuming order
    with click.progressbar(images, label='Scanning pages') as bar:
        for page_idx, image in enumerate(bar, 1):
            chunk_binaries = decode_qr_codes_from_image(image)
            all_chunk_binaries.extend(chunk_binaries)

    # Parse to get page numbers
    parsed = [parse_binary_chunk(c) for c in all_chunk_binaries if c]
    page_numbers = sorted([p['page_number'] for p in parsed if p])

    click.echo(f"Detected pages: {page_numbers}")

    if page_numbers != list(range(1, len(page_numbers) + 1)):
        click.echo("Pages were scanned out of order - reordering automatically...")

    # Reassemble (already sorts by page number internally)
    file_data, report = reassemble_chunks(all_chunk_binaries, ...)
```

### Test Plan

#### Unit Tests

**Test 1: Pages in Reverse Order**
```python
def test_pages_reverse_order():
    """Test decoding pages in reverse order."""
    # Create chunks for pages 1, 2, 3
    chunks = create_test_chunks([b"data1", b"data2", b"data3"])

    # Reverse order
    reversed_chunks = list(reversed(chunks))

    # Should still decode correctly
    result, report = reassemble_chunks(reversed_chunks)
    assert result == b"data1data2data3"  # Original order
```

**Test 2: Pages in Random Order**
```python
def test_pages_random_order():
    """Test decoding pages in random order."""
    import random

    chunks = create_test_chunks([b"A", b"B", b"C", b"D", b"E"])

    # Shuffle randomly
    shuffled = chunks.copy()
    random.shuffle(shuffled)

    result, report = reassemble_chunks(shuffled)
    assert result == b"ABCDE"  # Correct order
```

**Test 3: Interleaved Pages**
```python
def test_interleaved_pages():
    """Test pages in strange order (1, 5, 2, 4, 3)."""
    chunks = create_test_chunks([b"1", b"2", b"3", b"4", b"5"])

    # Reorder: 1, 5, 2, 4, 3
    weird_order = [chunks[0], chunks[4], chunks[1], chunks[3], chunks[2]]

    result, report = reassemble_chunks(weird_order)
    assert result == b"12345"
```

#### Integration Tests

**Test 4: Reverse Page Order in PDF**
```python
def test_decode_reversed_pdf():
    """Test decoding PDF with pages in reverse order."""
    # Encode normally
    encode_cmd('data.bin', 'normal.pdf')

    # Create reversed PDF (page N, N-1, ..., 2, 1)
    reverse_pdf_pages('normal.pdf', 'reversed.pdf')

    # Decode reversed PDF
    decode_cmd('reversed.pdf', 'recovered.bin')

    # Should still work
    assert files_identical('data.bin', 'recovered.bin')
```

**Test 5: Random Page Order in PDF**
```python
def test_decode_shuffled_pdf():
    """Test decoding PDF with randomly shuffled pages."""
    import random

    encode_cmd('data.bin', 'normal.pdf')

    # Shuffle pages randomly
    num_pages = get_pdf_page_count('normal.pdf')
    page_order = list(range(1, num_pages + 1))
    random.shuffle(page_order)

    reorder_pdf_pages('normal.pdf', 'shuffled.pdf', page_order)

    # Decode
    decode_cmd('shuffled.pdf', 'recovered.bin')

    assert files_identical('data.bin', 'recovered.bin')
```

**Test 6: Pages Scanned in Two Batches**
```python
def test_pages_in_batches():
    """Simulate scanning odd pages, then even pages."""
    # Encode 10-page document
    encode_cmd('data.bin', 'full.pdf')

    # Extract odd pages (1, 3, 5, 7, 9)
    extract_pages('full.pdf', 'odd.pdf', [1, 3, 5, 7, 9])

    # Extract even pages (2, 4, 6, 8, 10)
    extract_pages('full.pdf', 'even.pdf', [2, 4, 6, 8, 10])

    # Merge: odd first, then even (1,3,5,7,9,2,4,6,8,10)
    merge_pdfs(['odd.pdf', 'even.pdf'], 'merged.pdf')

    # Decode merged (out of order)
    decode_cmd('merged.pdf', 'recovered.bin')

    assert files_identical('data.bin', 'recovered.bin')
```

### User Experience

**Success output:**
```
Decoding: shuffled_backup.pdf
Converting PDF to images...
Found 5 pages
Reading QR codes...
Successfully decoded 19 QR codes from 5 pages
Detected pages: [1, 2, 3, 4, 5]
Reassembling data...
```

**Out-of-order output:**
```
Decoding: shuffled_backup.pdf
Converting PDF to images...
Found 5 pages
Reading QR codes...
Successfully decoded 19 QR codes from 5 pages
Detected pages: [1, 3, 5, 2, 4]
Pages were scanned out of order - reordering automatically...
Reassembling data...
```

### Success Criteria

- ✅ Pages can be scanned in any order
- ✅ Decoder automatically reorders by page number
- ✅ User is informed when pages are out of order
- ✅ Works with encryption
- ✅ Works with parity recovery
- ✅ All test cases pass

---

## Feature 4: Immediate Mixed Document Detection (Priority 1)

### Overview

Detect and error immediately when a page from a different document is encountered during decoding. This prevents confusion when scanning wrong pages or when pages from multiple documents get mixed together.

**Use Cases:**
- User accidentally scans pages from two different backups
- Pages from multiple documents stored together get mixed
- User scans wrong PDF file partway through
- Detect corruption/tampering early

### Current Behavior

Currently, MD5 validation happens in `reassemble_chunks()` AFTER all pages are decoded. We should detect mismatches DURING decoding for faster feedback.

### Design Decisions

**Detection Strategy:**
1. Decode first page, extract MD5 hash (reference MD5)
2. For each subsequent page:
   - Decode QR codes
   - Parse metadata
   - Check MD5 matches reference
   - **If different: ERROR immediately** (don't continue)
3. Only proceed to reassembly if all pages have same MD5

**Error Message:**
```
Error: Page 7 belongs to a different document!

Expected MD5: a1b2c3d4e5f6...
Found MD5:    f6e5d4c3b2a1...

This PDF contains pages from multiple QR code backups.
Please ensure all pages are from the same backup before decoding.
```

### Implementation Details

**Modify decode command:**

```python
@cli.command()
def decode(input_pdf, output, verify, recovery_mode, force):
    """Decode with immediate mixed document detection."""

    click.echo("Reading QR codes...")
    all_chunk_binaries = []
    reference_md5 = None
    reference_page = None

    with click.progressbar(images, label='Scanning pages') as bar:
        for page_idx, image in enumerate(bar, 1):
            chunk_binaries = decode_qr_codes_from_image(image)

            for chunk_binary in chunk_binaries:
                # Parse to get MD5
                parsed = parse_binary_chunk(chunk_binary)

                if parsed is None:
                    click.echo(f"\nWarning: Page {page_idx} - Failed to parse QR code", err=True)
                    continue

                # Check MD5 consistency
                if reference_md5 is None:
                    # First valid chunk sets reference
                    reference_md5 = parsed['md5_hash']
                    reference_page = parsed['page_number']
                    click.echo(f"\nDocument MD5: {reference_md5.hex()}")
                else:
                    # Verify subsequent chunks match
                    if parsed['md5_hash'] != reference_md5:
                        # MIXED DOCUMENT DETECTED
                        raise click.ClickException(
                            f"\n{'='*60}\n"
                            f"ERROR: Page {page_idx} belongs to a different document!\n\n"
                            f"Expected MD5 (from page {reference_page}): {reference_md5.hex()}\n"
                            f"Found MD5 (on page {page_idx}):    {parsed['md5_hash'].hex()}\n\n"
                            f"This PDF contains pages from multiple QR code backups.\n"
                            f"Please ensure all pages are from the same backup before decoding.\n"
                            f"{'='*60}"
                        )

                all_chunk_binaries.append(chunk_binary)

    # Continue with reassembly (MD5 already validated)
    file_data, report = reassemble_chunks(all_chunk_binaries, verify=verify, ...)
```

**Keep validation in reassemble_chunks():**

The existing validation in `reassemble_chunks()` should remain as a final check (defense in depth), but the decode command catches it earlier for better UX.

### Test Plan

#### Unit Tests

**Test 1: Mixed Documents in Chunks**
```python
def test_mixed_documents():
    """Test immediate detection of mixed documents."""
    md5_a = hashlib.md5(b"document_a").digest()
    md5_b = hashlib.md5(b"document_b").digest()

    # Create chunks from two different documents
    chunk1_a = md5_a + (1).to_bytes(2, 'big') + b"\x00" + (100).to_bytes(4, 'big') + b"data1"
    chunk2_a = md5_a + (2).to_bytes(2, 'big') + b"\x00" + b"data2"
    chunk3_b = md5_b + (3).to_bytes(2, 'big') + b"\x00" + b"data3"  # Different doc!

    # This is caught in reassemble_chunks (unit level)
    with pytest.raises(ValueError, match="Mixed documents detected"):
        reassemble_chunks([chunk1_a, chunk2_a, chunk3_b], verify=True)
```

#### Integration Tests

**Test 2: Mixed PDF Pages**
```python
def test_decode_mixed_pdf():
    """Test decoding PDF with pages from two different documents."""
    # Encode two different files
    encode_cmd('file_a.txt', 'backup_a.pdf')
    encode_cmd('file_b.txt', 'backup_b.pdf')

    # Create mixed PDF: pages 1-3 from A, pages 1-2 from B
    extract_pages('backup_a.pdf', 'pages_a.pdf', [1, 2, 3])
    extract_pages('backup_b.pdf', 'pages_b.pdf', [1, 2])
    merge_pdfs(['pages_a.pdf', 'pages_b.pdf'], 'mixed.pdf')

    # Try to decode
    with pytest.raises(ClickException, match="belongs to a different document"):
        decode_cmd('mixed.pdf', 'output.bin')
```

**Test 3: Single Wrong Page**
```python
def test_single_wrong_page():
    """Test PDF where just one page is from different document."""
    # Encode two documents
    encode_cmd('doc1.bin', 'backup1.pdf')  # 5 pages
    encode_cmd('doc2.bin', 'backup2.pdf')  # 3 pages

    # Create PDF: pages 1-3 from doc1, page 1 from doc2, page 4-5 from doc1
    mixed_pdf = create_mixed_pdf([
        ('backup1.pdf', 1),
        ('backup1.pdf', 2),
        ('backup1.pdf', 3),
        ('backup2.pdf', 1),  # WRONG!
        ('backup1.pdf', 4),
        ('backup1.pdf', 5),
    ])

    # Decode should fail when it hits page 4 (which is from doc2)
    with pytest.raises(ClickException) as exc_info:
        decode_cmd(mixed_pdf, 'output.bin')

    assert "Page 4 belongs to a different document" in str(exc_info.value)
```

**Test 4: All Pages from Different Document**
```python
def test_completely_wrong_pdf():
    """Test decoding PDF that's entirely the wrong document."""
    encode_cmd('file_a.txt', 'backup_a.pdf')
    encode_cmd('file_b.txt', 'backup_b.pdf')

    # User meant to decode backup_a but provided backup_b
    # Should work fine (all pages have same MD5)
    decode_cmd('backup_b.pdf', 'recovered.txt')

    # Should recover file_b, not file_a
    assert files_identical('file_b.txt', 'recovered.txt')
```

**Test 5: Mixed Documents with Encryption**
```python
def test_mixed_encrypted_documents():
    """Test mixed document detection with encrypted PDFs."""
    # Encode two encrypted documents
    encode_cmd('doc1.bin', 'enc1.pdf', encrypt=True, password='pass1')
    encode_cmd('doc2.bin', 'enc2.pdf', encrypt=True, password='pass2')

    # Mix pages
    mixed_pdf = merge_pdfs_alternating('enc1.pdf', 'enc2.pdf')

    # Should detect mixed documents before even attempting decryption
    with pytest.raises(ClickException, match="different document"):
        decode_cmd(mixed_pdf, 'output.bin', password='pass1')
```

**Test 6: Mixed Documents with Parity**
```python
def test_mixed_with_parity():
    """Test that parity pages must match MD5 of data pages."""
    # Encode two documents with parity
    encode_cmd('doc1.bin', 'backup1.pdf', parity=True)
    encode_cmd('doc2.bin', 'backup2.pdf', parity=True)

    # Create PDF: data pages from doc1, parity pages from doc2
    data_pages = extract_pages('backup1.pdf', pages=[1, 2, 3, 4])  # Data
    parity_pages = extract_pages('backup2.pdf', pages=[5])  # Parity from wrong doc
    mixed_pdf = merge_pdfs([data_pages, parity_pages])

    # Should error (parity MD5 doesn't match data MD5)
    with pytest.raises(ClickException, match="different document"):
        decode_cmd(mixed_pdf, 'output.bin')
```

### User Experience

**Normal decode (all pages same document):**
```
Decoding: backup.pdf
Converting PDF to images...
Found 5 pages
Reading QR codes...

Document MD5: a1b2c3d4e5f6789...
Successfully decoded 19 QR codes from 5 pages
Reassembling data...
```

**Mixed document detected:**
```
Decoding: mixed_backup.pdf
Converting PDF to images...
Found 10 pages
Reading QR codes...

Document MD5: a1b2c3d4e5f6789...
============================================================
ERROR: Page 7 belongs to a different document!

Expected MD5 (from page 1): a1b2c3d4e5f6789abcdef...
Found MD5 (on page 7):      f6e5d4c3b2a1987654321...

This PDF contains pages from multiple QR code backups.
Please ensure all pages are from the same backup before decoding.
============================================================
```

### Edge Cases

1. **First page is from wrong document**: Sets wrong reference MD5, but as long as all pages match, it works (user just scanned wrong file)
2. **Multiple documents interleaved**: Catches first mismatch
3. **Parity pages from different document**: Caught by MD5 check
4. **Encrypted pages mixed with unencrypted**: MD5s will differ (encrypted vs unencrypted data), caught
5. **Same file, different compression**: MD5s differ (different compressed data), caught - this is correct behavior
6. **Recovery mode**: Should still error on mixed documents (can't recover mixed data)

### Performance Impact

**Overhead:**
- Parsing metadata during decode: ~1-2ms per page (negligible)
- MD5 comparison: < 1µs per page (hash is already computed)
- Total impact: < 1% of decode time

**Benefit:**
- Faster feedback (error immediately, not after scanning all pages)
- Clearer error messages (shows which page is wrong)
- Prevents wasted time reassembling invalid data

### Success Criteria

- ✅ Detect mixed documents during page decoding
- ✅ Error immediately when mismatch found
- ✅ Clear error message showing which page is wrong
- ✅ Display both expected and found MD5 hashes
- ✅ Works with encryption
- ✅ Works with parity pages
- ✅ < 1% performance overhead
- ✅ All test cases pass

---

## Implementation Order

### Phase 2.0: Order-Independent Decoding & Mixed Document Detection (Week 1) ✅ COMPLETED

**Status:** ✅ Complete (2025-10-21)
**Commit:** 1645d6f

**Implementation Summary:**

**Days 1-2: Order-Independent Decoding**
- ✅ Add page number display to decode output
- ✅ Add out-of-order detection message
- ✅ Unit tests (reversed, shuffled, interleaved) - 4 tests passing
- ✅ Integration tests (reverse PDF pages, shuffle PDF pages) - 3 tests passing
- ✅ Documentation updates (CLAUDE.md, QR_CODE_BACKUP.md, README.md)

**Days 3-4: Mixed Document Detection**
- ✅ Add MD5 checking during decode (in decode command)
- ✅ Implement immediate error on MD5 mismatch
- ✅ Display reference MD5 on first page
- ✅ Unit tests (mixed chunks) - 3 tests passing
- ✅ Integration tests (mixed PDFs) - 3 tests passing

**Day 5:**
- ✅ Combined testing (both features together) - 4 tests passing
- ✅ Edge cases (shuffled mixed docs, missing pages, large documents)
- ✅ Documentation updates (all files updated)
- ✅ Created PDF helper utilities for testing

**Deliverables:**
- Modified: `qr_code_backup.py` (lines 912-974) - Enhanced decode() command
- New: `tests/pdf_helpers.py` - PDF manipulation utilities (6 functions)
- New: `tests/test_order_independence.py` - 3 integration tests
- New: `tests/test_mixed_documents.py` - 3 integration tests
- New: `tests/test_combined_features.py` - 4 combined tests
- Modified: `tests/test_decode.py` - Added 7 unit tests
- Updated: CLAUDE.md, QR_CODE_BACKUP.md, README.md

**Test Results:** 17/17 tests passing

**Rationale:** These features are:
- ✅ Simple to implement (mostly UI/UX improvements)
- ✅ High user value (prevent common mistakes)
- ✅ No new dependencies
- ✅ Foundation for parity recovery (need order-independence)

### Phase 2.1: Encryption (Weeks 2-3)

**Week 2:**
- [ ] Add dependencies (cryptography, argon2-cffi)
- [ ] Implement encryption functions (derive_key, encrypt_data, decrypt_data)
- [ ] Update binary metadata format for encryption
- [ ] Modify create_chunks() and reassemble_chunks()
- [ ] Unit tests for crypto functions

**Week 3:**
- [ ] Add CLI options (--encrypt, --encrypt-key-file, etc.)
- [ ] Implement password reading (stdin, key file)
- [ ] Integration tests (encode/decode encrypted)
- [ ] Edge case tests (wrong password, tampered data)
- [ ] Test with order-independent decoding and mixed document detection
- [ ] Documentation updates

### Phase 2.2: Parity Pages (Weeks 4-6)

**Week 4:**
- [ ] Add dependency (reedsolo)
- [ ] Implement parity generation (generate_parity_chunks)
- [ ] Implement parity recovery (recover_missing_chunks)
- [ ] Unit tests for parity functions

**Week 5:**
- [ ] Update binary metadata for parity flag
- [ ] Modify create_chunks() for parity generation
- [ ] Modify reassemble_chunks() for parity recovery
- [ ] Update decode flow (defer validation)
- [ ] Integration tests (encode/decode with parity)
- [ ] Test with order-independent decoding

**Week 6:**
- [ ] Add CLI options (--parity, --parity-pages)
- [ ] Update PDF headers for parity pages
- [ ] Edge case tests (too many missing, etc.)
- [ ] Combined tests (parity + encryption + order-independence)
- [ ] Documentation updates
- [ ] Manual print/scan tests

---

## Backward Compatibility

**Encryption:**
- Unencrypted PDFs created with v1.0 still decode normally
- Encryption flag = 0x00 for unencrypted (backward compatible)

**Parity:**
- PDFs without parity still decode normally
- Parity flag = 0x00 for data pages (backward compatible)
- If no parity pages found, falls back to existing validation

**Version Detection:**
- Can detect format version by checking flags in page 1
- Future: Add format version byte if needed

---

## Security Notes

**Encryption:**
- Argon2id prevents brute-force attacks on password
- AES-256-GCM provides confidentiality + integrity
- Verification hash enables fast password check
- No password length limit

**Parity:**
- Parity pages don't leak information about data
- Reed-Solomon works on encrypted data just fine
- Parity doesn't weaken encryption

**Combined:**
- Encrypt first, then parity (parity is over encrypted data)
- Even if parity pages recovered, data still encrypted
- Must have correct password to decrypt recovered data

---

## Future Enhancements (Phase 3)

1. **Steganography**: Hide QR codes in images
2. **QR code fingerprinting**: Detect which pages are from same document visually
3. **Progressive recovery**: Partial file recovery even without all pages
4. **Multi-file archives**: Combine multiple files in one PDF
5. **Compression tuning**: Let user choose compression level
6. **Error correction tuning**: Per-page error correction levels
7. **Web interface**: Browser-based encode/decode
8. **Mobile app**: Scan QR codes with phone camera

---

**Document Version:** 1.0
**Last Updated:** 2025-10-21
**Status:** Planning Phase
