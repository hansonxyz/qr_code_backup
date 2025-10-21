# Week 2-3: Encryption Implementation Plan

## Overview

Implement AES-256-GCM encryption with Argon2id key derivation for secure archival of sensitive data in QR code backups.

**Timeline:** 2 weeks (10 working days)
**Priority:** High
**Dependencies:** cryptography, argon2-cffi

---

## Goals

1. **Encrypt files** before encoding to QR codes using AES-256-GCM
2. **Secure key derivation** using Argon2id (memory-hard, GPU-resistant)
3. **Password verification** without full decryption attempt
4. **CLI integration** with password prompts and key file support
5. **Backward compatibility** with existing unencrypted PDFs
6. **Comprehensive testing** with 15+ test cases

---

## Week 2: Core Encryption Implementation (Days 1-5)

### Day 1: Dependencies and Environment Setup

**Tasks:**
1. Add dependencies to requirements.txt
2. Create encryption test fixtures
3. Set up test data for crypto operations

**Deliverables:**
```python
# requirements.txt additions
cryptography>=41.0.0      # For AES-256-GCM
argon2-cffi>=23.1.0       # For Argon2id
```

**Test Installation:**
```bash
pip install cryptography>=41.0.0 argon2-cffi>=23.1.0
python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('✓ cryptography')"
python3 -c "from argon2 import low_level; print('✓ argon2-cffi')"
```

**Acceptance Criteria:**
- ✅ Dependencies install without errors
- ✅ Can import AESGCM and argon2
- ✅ Test data files created

---

### Day 2: Argon2id Key Derivation Functions

**Tasks:**
1. Implement `derive_key()` function
2. Implement `create_verification_hash()` function
3. Implement `verify_password()` function
4. Unit tests for key derivation

**Functions to Implement:**

```python
def derive_key(password: str, salt: bytes, time_cost: int = 3,
               memory_cost: int = 65536, parallelism: int = 4) -> bytes:
    """Derive 32-byte key from password using Argon2id.

    Args:
        password: User password (string)
        salt: 16-byte random salt
        time_cost: Number of iterations (default: 3)
        memory_cost: Memory in KB (default: 65536 = 64MB)
        parallelism: Number of threads (default: 4)

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
    """Create verification hash from derived key using BLAKE2b.

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
        salt: Salt from metadata
        verification_hash: Hash from metadata
        time_cost, memory_cost, parallelism: Argon2 parameters

    Returns:
        True if password is correct
    """
    derived_key = derive_key(password, salt, time_cost, memory_cost, parallelism)
    computed_hash = create_verification_hash(derived_key)

    # Constant-time comparison to prevent timing attacks
    import hmac
    return hmac.compare_digest(computed_hash, verification_hash)
```

**Unit Tests:**

```python
def test_key_derivation_deterministic():
    """Test that same inputs produce same key."""
    password = "test_password_123"
    salt = b"1234567890123456"

    key1 = derive_key(password, salt, 3, 65536, 4)
    key2 = derive_key(password, salt, 3, 65536, 4)

    assert key1 == key2
    assert len(key1) == 32


def test_key_derivation_different_salts():
    """Test that different salts produce different keys."""
    password = "test_password"
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)

    key1 = derive_key(password, salt1)
    key2 = derive_key(password, salt2)

    assert key1 != key2


def test_verification_hash():
    """Test password verification."""
    password = "correct_password"
    wrong_password = "wrong_password"
    salt = os.urandom(16)

    key = derive_key(password, salt)
    verification_hash = create_verification_hash(key)

    # Correct password
    assert verify_password(password, salt, verification_hash, 3, 65536, 4)

    # Wrong password
    assert not verify_password(wrong_password, salt, verification_hash, 3, 65536, 4)


def test_argon2_parameters():
    """Test different Argon2 parameters."""
    password = "password"
    salt = os.urandom(16)

    # Different time costs produce different keys
    key1 = derive_key(password, salt, time_cost=2)
    key2 = derive_key(password, salt, time_cost=5)
    assert key1 != key2

    # Different memory costs produce different keys
    key3 = derive_key(password, salt, memory_cost=32768)
    key4 = derive_key(password, salt, memory_cost=131072)
    assert key3 != key4
```

**Acceptance Criteria:**
- ✅ Key derivation is deterministic
- ✅ Different salts/parameters produce different keys
- ✅ Password verification works correctly
- ✅ All 4 unit tests pass

---

### Day 3: AES-256-GCM Encryption Functions

**Tasks:**
1. Implement `encrypt_data()` function
2. Implement `decrypt_data()` function
3. Unit tests for encryption/decryption

**Functions to Implement:**

```python
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
```

**Unit Tests:**

```python
def test_encryption_decryption_round_trip():
    """Test encryption and decryption round trip."""
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


def test_tampered_ciphertext():
    """Test decryption fails if ciphertext is modified."""
    data = b"Secret data"
    password = "password123"

    enc_result = encrypt_data(data, password)

    # Tamper with ciphertext
    tampered = bytearray(enc_result['ciphertext'])
    tampered[10] ^= 0xFF  # Flip some bits

    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
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


def test_encryption_metadata():
    """Test encryption metadata structure."""
    data = b"Test"
    password = "pass"

    result = encrypt_data(data, password, time_cost=5, memory_cost=32768, parallelism=2)

    assert len(result['salt']) == 16
    assert len(result['nonce']) == 12
    assert len(result['verification_hash']) == 32
    assert result['time_cost'] == 5
    assert result['memory_cost'] == 32768
    assert result['parallelism'] == 2
    assert len(result['ciphertext']) > len(data)  # Has auth tag
```

**Acceptance Criteria:**
- ✅ Encryption/decryption round trip works
- ✅ Wrong password detected before decryption
- ✅ Tampered data causes InvalidTag exception
- ✅ All 4 unit tests pass

---

### Day 4: Binary Metadata Format Updates

**Tasks:**
1. Update `parse_binary_chunk()` to handle encryption flag
2. Update chunk building in `create_chunks()` for encrypted data
3. Unit tests for metadata parsing

**Binary Format Changes:**

**Page 1 (Encrypted):**
```
[Encryption Flag: 1 byte]         ← 0x01 for encrypted
[MD5: 16 bytes]                   ← MD5 of compressed+encrypted data
[Page#: 2 bytes]                  ← Page number
[FileSize: 4 bytes]               ← Original uncompressed file size
[Salt: 16 bytes]                  ← NEW
[Time Cost: 4 bytes]              ← NEW
[Memory Cost: 4 bytes]            ← NEW
[Parallelism: 4 bytes]            ← NEW
[Verification Hash: 32 bytes]     ← NEW
[Nonce: 12 bytes]                 ← NEW
[Data: variable]                  ← Encrypted chunk data
```

**Other Pages (Encrypted):**
```
[Encryption Flag: 1 byte]         ← 0x01
[MD5: 16 bytes]
[Page#: 2 bytes]
[Data: variable]
```

**Modified Functions:**

```python
def parse_binary_chunk(chunk_binary: bytes) -> Optional[Dict[str, Any]]:
    """Parse binary chunk with encryption support.

    Returns:
        Dictionary with parsed fields, or None if parsing fails
    """
    try:
        offset = 0

        # Read encryption flag (NEW)
        encrypted = chunk_binary[offset] != 0x00
        offset += 1

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

        # Page 1 has file size and possibly encryption metadata
        if page_num == 1:
            file_size = int.from_bytes(chunk_binary[offset:offset+4], 'big')
            offset += 4
            result['file_size'] = file_size

            if encrypted:
                # Read encryption metadata (NEW)
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
```

**Unit Tests:**

```python
def test_parse_unencrypted_chunk():
    """Test parsing unencrypted chunk (backward compatibility)."""
    md5 = hashlib.md5(b"data").digest()
    chunk = bytearray()
    chunk.append(0x00)  # Not encrypted
    chunk.extend(md5)
    chunk.extend((1).to_bytes(2, 'big'))  # Page 1
    chunk.extend((1000).to_bytes(4, 'big'))  # File size
    chunk.extend(b"compressed_data")

    parsed = parse_binary_chunk(bytes(chunk))

    assert parsed['encrypted'] == False
    assert parsed['md5_hash'] == md5
    assert parsed['page_number'] == 1
    assert parsed['file_size'] == 1000
    assert parsed['data'] == b"compressed_data"


def test_parse_encrypted_chunk_page1():
    """Test parsing encrypted page 1 with full metadata."""
    md5 = hashlib.md5(b"encrypted_data").digest()
    salt = os.urandom(16)
    verification_hash = os.urandom(32)
    nonce = os.urandom(12)

    chunk = bytearray()
    chunk.append(0x01)  # Encrypted
    chunk.extend(md5)
    chunk.extend((1).to_bytes(2, 'big'))  # Page 1
    chunk.extend((5000).to_bytes(4, 'big'))  # File size
    chunk.extend(salt)
    chunk.extend((3).to_bytes(4, 'big'))  # time_cost
    chunk.extend((65536).to_bytes(4, 'big'))  # memory_cost
    chunk.extend((4).to_bytes(4, 'big'))  # parallelism
    chunk.extend(verification_hash)
    chunk.extend(nonce)
    chunk.extend(b"encrypted_chunk_data")

    parsed = parse_binary_chunk(bytes(chunk))

    assert parsed['encrypted'] == True
    assert parsed['page_number'] == 1
    assert parsed['file_size'] == 5000
    assert parsed['salt'] == salt
    assert parsed['time_cost'] == 3
    assert parsed['memory_cost'] == 65536
    assert parsed['parallelism'] == 4
    assert parsed['verification_hash'] == verification_hash
    assert parsed['nonce'] == nonce
    assert parsed['data'] == b"encrypted_chunk_data"


def test_parse_encrypted_chunk_page2():
    """Test parsing encrypted page 2+ (no encryption metadata)."""
    md5 = hashlib.md5(b"encrypted_data").digest()

    chunk = bytearray()
    chunk.append(0x01)  # Encrypted
    chunk.extend(md5)
    chunk.extend((2).to_bytes(2, 'big'))  # Page 2
    chunk.extend(b"encrypted_chunk_data")

    parsed = parse_binary_chunk(bytes(chunk))

    assert parsed['encrypted'] == True
    assert parsed['page_number'] == 2
    assert 'file_size' not in parsed
    assert 'salt' not in parsed
    assert parsed['data'] == b"encrypted_chunk_data"
```

**Acceptance Criteria:**
- ✅ Can parse both encrypted and unencrypted chunks
- ✅ Backward compatible with existing format
- ✅ Encryption metadata extracted correctly
- ✅ All 3 unit tests pass

---

### Day 5: Integration with create_chunks() and reassemble_chunks()

**Tasks:**
1. Modify `create_chunks()` to support encryption
2. Modify `reassemble_chunks()` to support decryption
3. Integration tests for full cycle

**Modified create_chunks():**

```python
def create_chunks(file_path: str, chunk_size: int, compression: str = 'bzip2',
                 encrypt: bool = False, password: Optional[str] = None,
                 argon2_time: int = 3, argon2_memory: int = 65536,
                 argon2_parallelism: int = 4) -> List[bytes]:
    """Create chunks with optional encryption.

    Args:
        file_path: Path to file
        chunk_size: Chunk size in bytes
        compression: Compression method
        encrypt: Enable encryption
        password: Password for encryption
        argon2_time, argon2_memory, argon2_parallelism: Argon2 parameters

    Returns:
        List of binary chunks
    """
    # Read and compress file
    with open(file_path, 'rb') as f:
        file_data = f.read()

    file_size = len(file_data)
    compressed_data = compress_data(file_data, compression)

    # Optionally encrypt
    encryption_metadata = None
    if encrypt:
        if password is None:
            raise ValueError("Password required for encryption")

        click.echo("Encrypting...")
        enc_result = encrypt_data(
            compressed_data,
            password,
            time_cost=argon2_time,
            memory_cost=argon2_memory,
            parallelism=argon2_parallelism
        )
        data_to_chunk = enc_result['ciphertext']
        encryption_metadata = enc_result
    else:
        data_to_chunk = compressed_data

    # Calculate MD5 of (possibly encrypted) compressed data
    file_md5 = hashlib.md5(data_to_chunk).digest()

    # Create chunks
    chunks = []
    encryption_flag = 0x01 if encrypt else 0x00

    # Calculate chunk sizes accounting for metadata
    if encrypt:
        page1_data_size = chunk_size - 95  # Flag + MD5 + Page# + FileSize + Enc metadata
        other_page_data_size = chunk_size - 19  # Flag + MD5 + Page#
    else:
        page1_data_size = chunk_size - 23  # Flag + MD5 + Page# + FileSize
        other_page_data_size = chunk_size - 19  # Flag + MD5 + Page#

    offset = 0
    page_num = 1

    while offset < len(data_to_chunk):
        # Determine chunk size for this page
        if page_num == 1:
            this_chunk_size = page1_data_size
        else:
            this_chunk_size = other_page_data_size

        chunk_data = data_to_chunk[offset:offset + this_chunk_size]

        # Build binary chunk
        chunk_binary = bytearray()
        chunk_binary.append(encryption_flag)
        chunk_binary.extend(file_md5)
        chunk_binary.extend(page_num.to_bytes(2, 'big'))

        if page_num == 1:
            chunk_binary.extend(file_size.to_bytes(4, 'big'))

            if encrypt:
                # Add encryption metadata
                chunk_binary.extend(encryption_metadata['salt'])
                chunk_binary.extend(encryption_metadata['time_cost'].to_bytes(4, 'big'))
                chunk_binary.extend(encryption_metadata['memory_cost'].to_bytes(4, 'big'))
                chunk_binary.extend(encryption_metadata['parallelism'].to_bytes(4, 'big'))
                chunk_binary.extend(encryption_metadata['verification_hash'])
                chunk_binary.extend(encryption_metadata['nonce'])

        chunk_binary.extend(chunk_data)
        chunks.append(bytes(chunk_binary))

        offset += this_chunk_size
        page_num += 1

    if encrypt:
        click.echo(f"Encrypted with AES-256-GCM (Argon2id: t={argon2_time}, m={argon2_memory}KB, p={argon2_parallelism})")

    return chunks
```

**Modified reassemble_chunks():**

```python
def reassemble_chunks(chunk_binaries: List[bytes], verify: bool = True,
                     recovery_mode: bool = False,
                     password: Optional[str] = None) -> Tuple[bytes, Dict[str, Any]]:
    """Reassemble chunks with decryption support.

    Args:
        chunk_binaries: List of binary chunks
        verify: Verify MD5 and sequence
        recovery_mode: Attempt recovery
        password: Password for decryption (if encrypted)

    Returns:
        Tuple of (file_data, report_dict)
    """
    # Parse all chunks
    parsed_chunks = []
    for chunk_binary in chunk_binaries:
        parsed = parse_binary_chunk(chunk_binary)
        if parsed is None:
            if not recovery_mode:
                raise ValueError("Failed to parse chunk")
            continue
        parsed_chunks.append(parsed)

    if not parsed_chunks:
        raise ValueError("No valid chunks found")

    # Sort by page number
    parsed_chunks.sort(key=lambda x: x['page_number'])

    # Get page 1 for metadata
    page_1 = next((c for c in parsed_chunks if c['page_number'] == 1), None)
    if page_1 is None:
        raise ValueError("Page 1 not found")

    # MD5 consistency check (existing)
    reference_md5 = page_1['md5_hash']
    for chunk in parsed_chunks:
        if chunk['md5_hash'] != reference_md5:
            raise ValueError("MD5 mismatch - mixed documents detected")

    # Page sequence validation (existing)
    page_numbers = [c['page_number'] for c in parsed_chunks]
    expected_pages = set(range(1, max(page_numbers) + 1))
    actual_pages = set(page_numbers)
    missing_pages = sorted(expected_pages - actual_pages)

    if verify and missing_pages and not recovery_mode:
        raise ValueError(f"Missing pages: {missing_pages}")

    # Reassemble compressed (possibly encrypted) data
    compressed_data = b''.join([c['data'] for c in parsed_chunks])

    report = {
        'found_pages': len(actual_pages),
        'missing_pages': missing_pages,
        'md5_hash': reference_md5.hex(),
        'file_size': page_1['file_size'],
    }

    # Check if encrypted
    if page_1.get('encrypted'):
        if password is None:
            raise ValueError("Document is encrypted but no password provided")

        click.echo("Decrypting...")
        try:
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

    # Verify file size
    if len(file_data) != page_1['file_size']:
        raise ValueError(f"File size mismatch: expected {page_1['file_size']}, got {len(file_data)}")

    return file_data, report
```

**Integration Tests:**

```python
def test_create_chunks_encrypted():
    """Test creating encrypted chunks."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"Test data" * 100)
        test_file = f.name

    try:
        password = "test_password_123"
        chunks = create_chunks(
            test_file,
            chunk_size=300,
            compression='bzip2',
            encrypt=True,
            password=password
        )

        # Parse page 1
        parsed = parse_binary_chunk(chunks[0])
        assert parsed['encrypted'] == True
        assert 'salt' in parsed
        assert 'verification_hash' in parsed
        assert 'nonce' in parsed

        # Reassemble with password
        file_data, report = reassemble_chunks(chunks, password=password)

        with open(test_file, 'rb') as f:
            original = f.read()

        assert file_data == original
        assert report['decryption'] == 'success'
    finally:
        os.unlink(test_file)


def test_reassemble_encrypted_without_password():
    """Test that encrypted chunks fail without password."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"Secret data")
        test_file = f.name

    try:
        chunks = create_chunks(
            test_file,
            chunk_size=200,
            encrypt=True,
            password="secret"
        )

        with pytest.raises(ValueError, match="encrypted but no password"):
            reassemble_chunks(chunks, password=None)
    finally:
        os.unlink(test_file)


def test_reassemble_encrypted_wrong_password():
    """Test that wrong password is detected."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"Secret")
        test_file = f.name

    try:
        chunks = create_chunks(
            test_file,
            chunk_size=200,
            encrypt=True,
            password="correct"
        )

        with pytest.raises(ValueError, match="Incorrect password"):
            reassemble_chunks(chunks, password="wrong")
    finally:
        os.unlink(test_file)
```

**Acceptance Criteria:**
- ✅ Encrypted chunks created correctly
- ✅ Decryption works with correct password
- ✅ Error without password
- ✅ Wrong password detected
- ✅ All 3 integration tests pass

---

## Week 3: CLI Integration and Testing (Days 6-10)

### Day 6: Password Input Functions

**Tasks:**
1. Implement `read_password()` function
2. Add CLI options to encode/decode commands
3. Test password prompts

**Functions to Implement:**

```python
def read_password(key_file: Optional[str] = None, prompt_text: str = "Enter password") -> str:
    """Read password from key file or stdin.

    Args:
        key_file: Path to key file, or None to prompt
        prompt_text: Prompt text for stdin

    Returns:
        Password string (stripped of whitespace)
    """
    import click

    if key_file:
        try:
            with open(key_file, 'r', encoding='utf-8') as f:
                password = f.read().strip()
            if not password:
                raise ValueError(f"Key file is empty: {key_file}")
            return password
        except FileNotFoundError:
            raise click.ClickException(f"Key file not found: {key_file}")
        except Exception as e:
            raise click.ClickException(f"Error reading key file: {e}")
    else:
        password = click.prompt(prompt_text, hide_input=True).strip()
        if not password:
            raise click.ClickException("Password cannot be empty")
        return password
```

**CLI Options for encode:**

```python
@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), help='Output PDF path')
@click.option('--encrypt', is_flag=True, help='Encrypt file before encoding')
@click.option('--encrypt-key-file', type=click.Path(exists=True), help='Read password from file')
@click.option('--argon2-time', type=int, default=3, help='Argon2 time cost')
@click.option('--argon2-memory', type=int, default=65536, help='Argon2 memory cost (KB)')
@click.option('--argon2-parallelism', type=int, default=4, help='Argon2 parallelism')
# ... existing options ...
def encode(input_file, output, encrypt, encrypt_key_file, argon2_time, argon2_memory, argon2_parallelism, ...):
    """Encode file with optional encryption."""

    # Get password if encryption requested
    password = None
    if encrypt:
        password = read_password(
            key_file=encrypt_key_file,
            prompt_text="Enter encryption password"
        )

        # Confirm password if prompted (not from key file)
        if not encrypt_key_file:
            confirm = read_password(prompt_text="Confirm password")
            if password != confirm:
                raise click.ClickException("Passwords do not match")

    # Create chunks with encryption
    chunks = create_chunks(
        input_file,
        chunk_size=chunk_size,
        compression='bzip2',
        encrypt=encrypt,
        password=password,
        argon2_time=argon2_time,
        argon2_memory=argon2_memory,
        argon2_parallelism=argon2_parallelism
    )

    # ... rest of encode logic ...
```

**CLI Options for decode:**

```python
@cli.command()
@click.argument('input_pdf', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, type=click.Path(), help='Output file path')
@click.option('--decrypt-key-file', type=click.Path(exists=True), help='Read password from file')
# ... existing options ...
def decode(input_pdf, output, decrypt_key_file, ...):
    """Decode PDF with automatic encryption detection."""

    # ... decode QR codes ...

    # Check if encrypted by parsing page 1
    page_1 = parse_binary_chunk(all_chunk_binaries[0])

    password = None
    if page_1 and page_1.get('encrypted'):
        click.echo("Document is encrypted")
        password = read_password(
            key_file=decrypt_key_file,
            prompt_text="Enter decryption password"
        )

    # Reassemble with password
    file_data, report = reassemble_chunks(
        all_chunk_binaries,
        verify=verify,
        recovery_mode=recovery_mode,
        password=password
    )

    # ... write output ...
```

**Acceptance Criteria:**
- ✅ Password prompting works
- ✅ Key file reading works
- ✅ Password confirmation for encode
- ✅ Auto-detection of encryption for decode
- ✅ Empty password rejected

---

### Day 7-8: End-to-End Integration Tests

**Tasks:**
1. Full encode-decode cycle tests
2. Key file tests
3. Edge case tests
4. Performance tests

**Integration Tests:**

```python
def test_full_encrypted_cycle():
    """Test complete encode-decode cycle with encryption."""
    test_data = b"Sensitive information" * 100
    password = "encryption_password_123"

    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = os.path.join(tmpdir, 'input.bin')
        pdf_file = os.path.join(tmpdir, 'encrypted.pdf')
        output_file = os.path.join(tmpdir, 'output.bin')

        # Write test data
        with open(input_file, 'wb') as f:
            f.write(test_data)

        # Encode with encryption
        chunks = create_chunks(input_file, chunk_size=300, encrypt=True, password=password)
        qr_images = [create_qr_code(chunk, qr_version=18, error_correction='M') for chunk in chunks]
        generate_pdf(qr_images, output_path=pdf_file, title='Encrypted Test', ...)

        # Decode
        images = pdf_to_images(pdf_file)
        all_chunks = []
        for image in images:
            chunk_binaries = decode_qr_codes_from_image(image)
            all_chunks.extend(chunk_binaries)

        file_data, report = reassemble_chunks(all_chunks, password=password)

        # Write output
        with open(output_file, 'wb') as f:
            f.write(file_data)

        # Verify
        assert filecmp.cmp(input_file, output_file)
        assert report['decryption'] == 'success'


def test_key_file_encryption():
    """Test encryption/decryption with key file."""
    test_data = b"Data to encrypt"

    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = os.path.join(tmpdir, 'input.bin')
        key_file = os.path.join(tmpdir, 'key.txt')
        pdf_file = os.path.join(tmpdir, 'encrypted.pdf')
        output_file = os.path.join(tmpdir, 'output.bin')

        # Write test data
        with open(input_file, 'wb') as f:
            f.write(test_data)

        # Write key file (with newline)
        with open(key_file, 'w') as f:
            f.write('my_secure_password\n')

        # Read password from key file
        password = read_password(key_file=key_file)
        assert password == 'my_secure_password'  # Stripped

        # Encode
        chunks = create_chunks(input_file, chunk_size=200, encrypt=True, password=password)
        # ... generate PDF ...

        # Decode with same key file
        # ... decode PDF ...
        file_data, report = reassemble_chunks(all_chunks, password=password)

        # Write and verify
        with open(output_file, 'wb') as f:
            f.write(file_data)
        assert filecmp.cmp(input_file, output_file)


def test_encryption_with_custom_argon2_params():
    """Test encryption with custom Argon2 parameters."""
    test_data = b"Test"
    password = "password"

    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = os.path.join(tmpdir, 'input.bin')
        output_file = os.path.join(tmpdir, 'output.bin')

        with open(input_file, 'wb') as f:
            f.write(test_data)

        # Encode with custom params
        chunks = create_chunks(
            input_file,
            chunk_size=200,
            encrypt=True,
            password=password,
            argon2_time=5,
            argon2_memory=131072,  # 128MB
            argon2_parallelism=8
        )

        # Decode (params are in metadata)
        file_data, report = reassemble_chunks(chunks, password=password)

        with open(output_file, 'wb') as f:
            f.write(file_data)

        assert filecmp.cmp(input_file, output_file)


def test_encryption_performance():
    """Test encryption performance for 25KB file."""
    import time

    test_data = os.urandom(25 * 1024)  # 25KB random data
    password = "performance_test"

    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = os.path.join(tmpdir, 'input.bin')

        with open(input_file, 'wb') as f:
            f.write(test_data)

        # Time encryption
        start = time.time()
        chunks = create_chunks(input_file, chunk_size=300, encrypt=True, password=password)
        encrypt_time = time.time() - start

        # Time decryption
        start = time.time()
        file_data, report = reassemble_chunks(chunks, password=password)
        decrypt_time = time.time() - start

        # Should be fast (< 2 seconds each)
        assert encrypt_time < 2.0, f"Encryption too slow: {encrypt_time:.2f}s"
        assert decrypt_time < 2.0, f"Decryption too slow: {decrypt_time:.2f}s"

        # Verify correctness
        assert file_data == test_data


def test_special_characters_in_password():
    """Test passwords with special characters."""
    passwords_to_test = [
        "password with spaces",
        "pássword_with_ûnicode",
        "p@ssw0rd!#$%^&*()",
        "🔒🔑 emoji password",
    ]

    test_data = b"Secret"

    for password in passwords_to_test:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            with open(input_file, 'wb') as f:
                f.write(test_data)

            chunks = create_chunks(input_file, chunk_size=200, encrypt=True, password=password)
            file_data, report = reassemble_chunks(chunks, password=password)

            assert file_data == test_data


def test_very_long_password():
    """Test with 100+ character password."""
    password = "a" * 150
    test_data = b"Data"

    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = os.path.join(tmpdir, 'input.bin')
        with open(input_file, 'wb') as f:
            f.write(test_data)

        chunks = create_chunks(input_file, chunk_size=200, encrypt=True, password=password)
        file_data, report = reassemble_chunks(chunks, password=password)

        assert file_data == test_data


def test_backward_compatibility_unencrypted():
    """Test that unencrypted PDFs still work (backward compatibility)."""
    test_data = b"Unencrypted data"

    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = os.path.join(tmpdir, 'input.bin')
        with open(input_file, 'wb') as f:
            f.write(test_data)

        # Create chunks without encryption (old style)
        chunks = create_chunks(input_file, chunk_size=200, encrypt=False)

        # Decode without password
        file_data, report = reassemble_chunks(chunks, password=None)

        assert file_data == test_data
        assert 'decryption' not in report  # No decryption happened
```

**Acceptance Criteria:**
- ✅ Full encrypted cycle works
- ✅ Key file support works
- ✅ Custom Argon2 parameters work
- ✅ Performance < 2 seconds for 25KB
- ✅ Special characters in password work
- ✅ Long passwords work
- ✅ Backward compatibility maintained
- ✅ All 7 integration tests pass

---

### Day 9: Documentation Updates

**Tasks:**
1. Update README.md with encryption examples
2. Update CLAUDE.md with architecture details
3. Update QR_CODE_BACKUP.md with technical specs
4. Add CLI help text
5. Create encryption usage guide

**Documentation Sections to Add:**

**README.md:**
```markdown
### Encryption

Encrypt sensitive files before encoding to QR codes:

\```bash
# Encrypt with password prompt
python qr_code_backup.py encode secrets.txt -o backup.pdf --encrypt

# Encrypt with key file
python qr_code_backup.py encode secrets.txt -o backup.pdf --encrypt-key-file password.txt

# Decrypt (auto-detected)
python qr_code_backup.py decode backup.pdf -o recovered.txt

# Decrypt with key file
python qr_code_backup.py decode backup.pdf -o recovered.txt --decrypt-key-file password.txt
\```

**Security Features:**
- AES-256-GCM authenticated encryption
- Argon2id key derivation (memory-hard, GPU-resistant)
- Fast password verification before decryption attempt
- Quantum-safe symmetric encryption
```

**CLAUDE.md - Add to Architecture Decisions:**
```markdown
### Encryption Architecture

**Encryption Pipeline:**
1. Read file → Compress (bzip2) → Encrypt (AES-256-GCM) → Chunk → QR encode

**Key Derivation:**
- Argon2id with configurable parameters
- Default: time=3, memory=64MB, parallelism=4
- ~0.5-1 second derivation time

**Password Verification:**
- BLAKE2b hash of derived key stored in metadata
- Allows fast password check without full decryption
- Constant-time comparison prevents timing attacks

**Binary Format:**
- Encryption flag (1 byte): 0x00 = unencrypted, 0x01 = encrypted
- Page 1 includes: salt, Argon2 params, verification hash, nonce
- Other pages only have flag
- Backward compatible (unencrypted = flag 0x00)
```

**Acceptance Criteria:**
- ✅ README.md updated with examples
- ✅ CLAUDE.md updated with architecture
- ✅ QR_CODE_BACKUP.md updated with specs
- ✅ CLI help text complete
- ✅ All documentation reviewed

---

### Day 10: Final Testing and Validation

**Tasks:**
1. Run full test suite
2. Manual testing scenarios
3. Edge case validation
4. Performance benchmarking
5. Security review

**Manual Test Scenarios:**

1. **Basic encrypted encode-decode:**
   - Encode 5KB file with encryption
   - Verify PDF looks correct
   - Decode with correct password
   - Verify files match

2. **Wrong password:**
   - Try to decode with wrong password
   - Verify clear error message
   - Verify fast failure (< 1 second)

3. **Key file with trailing newline:**
   - Create key file with `echo "password\n" > key.txt`
   - Encode/decode using key file
   - Verify newline is stripped

4. **Empty password:**
   - Try to encode with empty password
   - Verify error message

5. **Encrypted + Out-of-Order Pages:**
   - Encode encrypted file to multi-page PDF
   - Shuffle pages
   - Decode with password
   - Verify recovery works

6. **Large file encryption:**
   - Encode 25KB file with encryption
   - Measure time (should be < 5 seconds total)
   - Decode and verify

**Security Checklist:**

- ✅ Passwords not logged or displayed
- ✅ Key derivation uses cryptographically secure random
- ✅ Constant-time password comparison
- ✅ No password length limits
- ✅ Authenticated encryption (AES-GCM)
- ✅ Unique nonce per encryption
- ✅ Tampered data detected
- ✅ Memory-hard KDF (Argon2id)

**Acceptance Criteria:**
- ✅ All 15+ unit tests pass
- ✅ All 10+ integration tests pass
- ✅ All manual tests pass
- ✅ Performance targets met
- ✅ Security checklist complete
- ✅ No regressions in existing features

---

## Success Criteria Summary

**Week 2 Deliverables:**
- ✅ Crypto dependencies installed
- ✅ Key derivation functions (3 functions, 4 tests)
- ✅ Encryption functions (2 functions, 4 tests)
- ✅ Binary metadata updates (1 function, 3 tests)
- ✅ Integration with create_chunks/reassemble_chunks (3 tests)

**Week 3 Deliverables:**
- ✅ Password input functions
- ✅ CLI integration (encode/decode commands)
- ✅ End-to-end integration tests (7 tests)
- ✅ Documentation updates (3 files)
- ✅ Final validation and testing

**Total Test Coverage:** 24+ tests
**Performance:** < 2 seconds encryption/decryption for 25KB file
**Security:** Argon2id + AES-256-GCM + verification hash
**Backward Compatibility:** Unencrypted PDFs still work

---

## Risk Mitigation

**Potential Issues:**

1. **Argon2 performance on low-memory systems:**
   - Mitigation: Allow custom memory_cost parameter
   - Default 64MB is reasonable for most systems

2. **Password input in automated scripts:**
   - Mitigation: Support key file option
   - Document piping password via stdin

3. **Metadata size increase:**
   - Mitigation: Only page 1 has encryption metadata (+73 bytes)
   - Other pages only +1 byte

4. **Compatibility with existing PDFs:**
   - Mitigation: Encryption flag clearly indicates format
   - Old code will error clearly if it doesn't support encryption

---

## Next Steps After Week 2-3

After encryption is complete, the next feature is **Parity Pages (Weeks 4-6)**:
- Reed-Solomon error correction at document level
- Recover from missing pages using parity pages
- Works with encrypted data
- Default: 1 parity page per 20 data pages

---

**Plan Version:** 1.0
**Last Updated:** 2025-10-21
**Estimated Duration:** 10 working days (2 weeks)
