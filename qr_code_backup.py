#!/usr/bin/env python3
"""
QR Code Backup Tool - Archive data as printable QR codes for long-term offline storage

This tool encodes files into multi-page PDF documents containing QR codes with error
correction, and can decode scanned PDFs back into the original files.

REQUIREMENTS:
  Python 3.8+

  Install Python dependencies with:
    pip install -r requirements.txt

  System dependencies (for pyzbar):
    - Linux: sudo apt-get install libzbar0
    - macOS: brew install zbar
    - Windows: Download from http://zbar.sourceforge.net/

USAGE:
  Encode a file:
    python qr_code_backup.py encode myfile.txt -o output.pdf

  Decode a scanned PDF:
    python qr_code_backup.py decode scanned.pdf -o recovered.txt

  View PDF metadata:
    python qr_code_backup.py info output.pdf

For detailed help on each command:
    python qr_code_backup.py encode --help
    python qr_code_backup.py decode --help
    python qr_code_backup.py info --help
"""

import sys
import os
import json
import hashlib
import base64
import gzip
import bz2
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import io

import click
import qrcode
from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H
from PIL import Image
from reportlab.lib.pagesizes import A4, LETTER, LEGAL
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas as pdf_canvas
from pyzbar import pyzbar
import cv2
import numpy as np
from pypdf import PdfReader, PdfWriter

# Version and format constants
VERSION = "2.0.0"
FORMAT_VERSION = "1.0"

# QR Code error correction mapping
ERROR_CORRECTION_LEVELS = {
    'L': ERROR_CORRECT_L,  # ~7% error correction
    'M': ERROR_CORRECT_M,  # ~15% error correction (default)
    'Q': ERROR_CORRECT_Q,  # ~25% error correction
    'H': ERROR_CORRECT_H,  # ~30% error correction
}

# Page size mapping
PAGE_SIZES = {
    'A4': A4,
    'LETTER': LETTER,
    'LEGAL': LEGAL,
}


# ============================================================================
# ENCODING FUNCTIONS
# ============================================================================

def calculate_checksum(data: bytes, algorithm: str = 'sha256') -> str:
    """Calculate hash checksum of data.

    Args:
        data: Bytes to hash
        algorithm: Hash algorithm (sha256, md5)

    Returns:
        Hex string of hash
    """
    if algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def compress_data(data: bytes, compression: str) -> bytes:
    """Compress data using specified algorithm.

    Args:
        data: Data to compress
        compression: Algorithm - 'none', 'gzip', 'bzip2'

    Returns:
        Compressed data (or original if compression='none')
    """
    if compression == 'none':
        return data
    elif compression == 'gzip':
        return gzip.compress(data)
    elif compression == 'bzip2':
        return bz2.compress(data)
    else:
        raise ValueError(f"Unsupported compression: {compression}")


def decompress_data(data: bytes, compression: str) -> bytes:
    """Decompress data using specified algorithm.

    Args:
        data: Data to decompress
        compression: Algorithm - 'none', 'gzip', 'bzip2'

    Returns:
        Decompressed data (or original if compression='none')
    """
    if compression == 'none':
        return data
    elif compression == 'gzip':
        return gzip.decompress(data)
    elif compression == 'bzip2':
        return bz2.decompress(data)
    else:
        raise ValueError(f"Unsupported compression: {compression}")


# ============================================================================
# Encryption Functions (AES-256-GCM with Argon2id Key Derivation)
# ============================================================================

def derive_key(password: str, salt: bytes, time_cost: int = 3,
               memory_cost: int = 65536, parallelism: int = 4) -> bytes:
    """Derive 32-byte encryption key from password using Argon2id.

    Argon2id is a memory-hard key derivation function that is resistant
    to GPU and ASIC attacks. It won the Password Hashing Competition.

    Args:
        password: User password (string)
        salt: 16-byte random salt
        time_cost: Number of iterations (default: 3)
        memory_cost: Memory in KB (default: 65536 = 64MB)
        parallelism: Number of threads (default: 4)

    Returns:
        32-byte derived key for AES-256

    Raises:
        ImportError: If argon2-cffi is not installed
    """
    try:
        from argon2 import low_level
    except ImportError:
        raise ImportError(
            "argon2-cffi is required for encryption. "
            "Install it with: pip install argon2-cffi>=23.1.0"
        )

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

    The verification hash allows fast password verification without
    attempting full decryption. It's stored in the PDF metadata.

    Args:
        key: 32-byte derived key

    Returns:
        32-byte BLAKE2b hash of the key
    """
    return hashlib.blake2b(key, digest_size=32).digest()


def verify_password(password: str, salt: bytes, verification_hash: bytes,
                   time_cost: int, memory_cost: int, parallelism: int) -> bool:
    """Verify password against stored verification hash.

    This provides fast password verification before attempting decryption.
    Uses constant-time comparison to prevent timing attacks.

    Args:
        password: User-provided password
        salt: Salt from page 1 metadata
        verification_hash: Verification hash from page 1 metadata
        time_cost, memory_cost, parallelism: Argon2 parameters from metadata

    Returns:
        True if password is correct, False otherwise
    """
    derived_key = derive_key(password, salt, time_cost, memory_cost, parallelism)
    computed_hash = create_verification_hash(derived_key)

    # Constant-time comparison to prevent timing attacks
    import hmac
    return hmac.compare_digest(computed_hash, verification_hash)


def encrypt_data(data: bytes, password: str, time_cost: int = 3,
                memory_cost: int = 65536, parallelism: int = 4) -> dict:
    """Encrypt data with AES-256-GCM authenticated encryption.

    AES-256-GCM provides both confidentiality and authenticity. The GCM
    mode includes an authentication tag that detects any tampering.

    Args:
        data: Data to encrypt (compressed file data)
        password: User password
        time_cost: Argon2 time cost (default: 3)
        memory_cost: Argon2 memory cost in KB (default: 65536 = 64MB)
        parallelism: Argon2 parallelism (default: 4)

    Returns:
        Dictionary containing:
            - salt: 16-byte random salt
            - nonce: 12-byte random nonce for GCM
            - verification_hash: 32-byte password verification hash
            - time_cost, memory_cost, parallelism: Argon2 parameters
            - ciphertext: Encrypted data with authentication tag

    Raises:
        ImportError: If cryptography is not installed
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ImportError(
            "cryptography is required for encryption. "
            "Install it with: pip install cryptography>=41.0.0"
        )

    import os

    # Generate cryptographically secure random salt and nonce
    salt = os.urandom(16)  # 128 bits
    nonce = os.urandom(12)  # 96 bits (recommended for GCM)

    # Derive key from password using Argon2id
    key = derive_key(password, salt, time_cost, memory_cost, parallelism)

    # Create verification hash for fast password checking
    verification_hash = create_verification_hash(key)

    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)  # No additional associated data

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

    Verifies the password first using the verification hash before attempting
    decryption. If the ciphertext has been tampered with, decryption will fail
    with an InvalidTag exception.

    Args:
        ciphertext: Encrypted data (includes GCM authentication tag)
        password: User password
        salt: 16-byte salt from metadata
        nonce: 12-byte nonce from metadata
        verification_hash: 32-byte verification hash from metadata
        time_cost, memory_cost, parallelism: Argon2 parameters from metadata

    Returns:
        Decrypted plaintext data

    Raises:
        ValueError: If password is incorrect
        cryptography.exceptions.InvalidTag: If data has been tampered with
        ImportError: If cryptography is not installed
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ImportError(
            "cryptography is required for decryption. "
            "Install it with: pip install cryptography>=41.0.0"
        )

    # Verify password first (fast check before expensive decryption)
    if not verify_password(password, salt, verification_hash,
                          time_cost, memory_cost, parallelism):
        raise ValueError("Incorrect password")

    # Derive key from password
    key = derive_key(password, salt, time_cost, memory_cost, parallelism)

    # Decrypt with AES-256-GCM
    # Will raise InvalidTag if data has been tampered with
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext


# ============================================================================
# PARITY FUNCTIONS (Reed-Solomon for page recovery)
# ============================================================================

def calculate_parity_count(num_data_pages: int, parity_percent: float = 5.0) -> int:
    """Calculate number of parity pages needed based on percentage.

    Parity count is rounded up to the nearest multiple of 4 to ensure
    parity QR codes fill complete pages (4 QR codes per page in 2x2 grid).

    Args:
        num_data_pages: Number of data pages
        parity_percent: Percentage of data pages to use as parity (0-100)
                       Default 5.0 = 5% overhead

    Returns:
        Number of parity pages to generate, rounded to multiple of 4
        (0 if parity_percent is 0)

    Example:
        >>> calculate_parity_count(20)  # 5% of 20 = 1 → rounds to 4
        4
        >>> calculate_parity_count(100)  # 5% of 100 = 5 → rounds to 8
        8
        >>> calculate_parity_count(20, parity_percent=10.0)  # 10% of 20 = 2 → rounds to 4
        4
        >>> calculate_parity_count(20, parity_percent=0.0)  # Disabled
        0
    """
    if parity_percent == 0.0:
        return 0

    import math
    base_count = math.ceil((parity_percent / 100.0) * num_data_pages)

    # Round up to nearest multiple of 4 (for complete pages)
    return math.ceil(base_count / 4) * 4


def pad_chunks(chunks: List[bytes]) -> Tuple[List[bytes], int]:
    """Pad all chunks to same size (required for Reed-Solomon).

    Reed-Solomon works on fixed-size symbols, so all chunks must be
    the same length. Shorter chunks are padded with zero bytes.

    Args:
        chunks: List of variable-size chunks

    Returns:
        Tuple of (padded_chunks, max_size)
        - padded_chunks: All chunks padded to max_size
        - max_size: The maximum chunk size (used for padding)

    Example:
        >>> chunks = [b"ab", b"abcd", b"a"]
        >>> padded, size = pad_chunks(chunks)
        >>> size
        4
        >>> padded
        [b'ab\\x00\\x00', b'abcd', b'a\\x00\\x00\\x00']
    """
    max_size = max(len(chunk) for chunk in chunks)

    padded = []
    for chunk in chunks:
        if len(chunk) < max_size:
            # Pad with zero bytes
            padded.append(chunk + b'\x00' * (max_size - len(chunk)))
        else:
            padded.append(chunk)

    return padded, max_size


def generate_parity_chunks(data_chunks: List[bytes], num_parity: int) -> List[bytes]:
    """Generate parity chunks using Reed-Solomon erasure codes.

    This function computes "vertical" parity across chunks:
    - For each byte position (0 to chunk_size-1):
      - Collect byte from that position in all data chunks
      - Compute Reed-Solomon parity bytes
      - Store in corresponding parity chunks

    This approach allows recovery of up to N missing chunks with N parity chunks.

    Args:
        data_chunks: List of data chunks (must all be same size)
        num_parity: Number of parity chunks to generate

    Returns:
        List of parity chunks (length = num_parity)

    Example:
        >>> data = [b"AAAA", b"BBBB", b"CCCC"]
        >>> parity = generate_parity_chunks(data, num_parity=1)
        >>> len(parity)
        1
        >>> len(parity[0])
        4

    Note:
        All data chunks must be the same size. Use pad_chunks() first if needed.
    """
    from reedsolo import RSCodec

    if not data_chunks:
        raise ValueError("No data chunks provided")

    # Verify all chunks are same size
    chunk_size = len(data_chunks[0])
    if not all(len(chunk) == chunk_size for chunk in data_chunks):
        raise ValueError("All data chunks must be same size (use pad_chunks first)")

    # Create Reed-Solomon codec
    rs = RSCodec(nsym=num_parity)

    # Initialize parity chunks
    parity_chunks = [bytearray() for _ in range(num_parity)]

    # Process each byte position across all chunks
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
    """Recover missing chunks using Reed-Solomon parity data.

    Uses erasure decoding to reconstruct missing chunks from available
    data chunks and parity chunks. Can recover up to N missing chunks
    if N parity chunks are available.

    Args:
        all_chunks: List with None for missing chunks (e.g., [b"A", None, b"C"])
        parity_chunks: List of parity chunks
        num_data_chunks: Expected number of data chunks

    Returns:
        List of recovered data chunks (no None values)

    Raises:
        ValueError: If too many chunks missing to recover

    Example:
        >>> data = [b"AAAA", b"BBBB", b"CCCC"]
        >>> parity = generate_parity_chunks(data, num_parity=1)
        >>> incomplete = [b"AAAA", None, b"CCCC"]  # Missing b"BBBB"
        >>> recovered = recover_missing_chunks(incomplete, parity, 3)
        >>> recovered[1]
        b'BBBB'
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
        # Nothing missing - return data chunks as-is
        return all_chunks[:num_data_chunks]

    chunk_size = len(parity_chunks[0])

    # Initialize recovered chunks
    recovered_chunks = []
    for i in range(num_data_chunks):
        if all_chunks[i] is not None:
            recovered_chunks.append(all_chunks[i])
        else:
            recovered_chunks.append(bytearray(chunk_size))

    # Recover byte-by-byte
    for byte_pos in range(chunk_size):
        # Build byte array: data bytes + parity bytes
        data_bytes = bytearray()
        for i in range(num_data_chunks):
            if all_chunks[i] is not None:
                data_bytes.append(all_chunks[i][byte_pos])
            else:
                data_bytes.append(0)  # Placeholder for missing

        # Add parity bytes
        for parity_chunk in parity_chunks:
            data_bytes.append(parity_chunk[byte_pos])

        # Decode with erasure positions
        try:
            decoded = rs.decode(data_bytes, erase_pos=missing_positions)

            # Update recovered chunks at missing positions
            for i in missing_positions:
                recovered_chunks[i][byte_pos] = decoded[0][i]
        except Exception as e:
            raise ValueError(f"Parity recovery failed at byte {byte_pos}: {e}")

    return [bytes(chunk) if isinstance(chunk, bytearray) else chunk
            for chunk in recovered_chunks]


def get_qr_modules(qr_version: int) -> int:
    """Get the number of modules (pixels) per side for a QR code version.

    Args:
        qr_version: QR code version (1-40)

    Returns:
        Number of modules per side
    """
    # QR code formula: modules = 4 * version + 17
    return 4 * qr_version + 17


def calculate_qr_physical_size(qr_version: int, module_size_mm: float, border: int = 1) -> float:
    """Calculate the physical size of a QR code.

    Args:
        qr_version: QR code version
        module_size_mm: Size of each module in millimeters
        border: Border size in modules (default: 4)

    Returns:
        Physical size in millimeters
    """
    modules = get_qr_modules(qr_version)
    # Add border on each side
    total_modules = modules + 2 * border
    return total_modules * module_size_mm


def calculate_grid_layout(page_width_mm: float, page_height_mm: float,
                         qr_size_mm: float, margin_mm: float, spacing_mm: float,
                         header_height_mm: float) -> Tuple[int, int]:
    """Calculate optimal grid layout (rows, columns) for QR codes.

    Args:
        page_width_mm: Page width in millimeters
        page_height_mm: Page height in millimeters
        qr_size_mm: QR code size in millimeters
        margin_mm: Page margin in millimeters
        spacing_mm: Spacing between QR codes in millimeters
        header_height_mm: Header height in millimeters (0 if no header)

    Returns:
        Tuple of (rows, columns)
    """
    # Calculate available space
    available_width = page_width_mm - 2 * margin_mm
    available_height = page_height_mm - 2 * margin_mm - header_height_mm

    # Calculate how many QR codes fit
    # Formula: floor((available + spacing) / (qr_size + spacing))
    # The +spacing accounts for the fact that the last QR code doesn't need trailing spacing
    cols = max(1, int((available_width + spacing_mm) / (qr_size_mm + spacing_mm)))
    rows = max(1, int((available_height + spacing_mm) / (qr_size_mm + spacing_mm)))

    return (rows, cols)


def calculate_optimal_qr_version(module_size_mm: float, page_width_mm: float,
                                 page_height_mm: float, margin_mm: float,
                                 spacing_mm: float, header_height_mm: float,
                                 min_qr_codes_per_page: int = 4) -> int:
    """Calculate the optimal QR version that fits the desired grid layout.

    Finds the largest QR code version that still allows at least min_qr_codes_per_page
    to fit on a page (typically 4 for a 2x2 grid).

    Args:
        module_size_mm: Size of each QR module in millimeters
        page_width_mm: Page width in millimeters
        page_height_mm: Page height in millimeters
        margin_mm: Page margin in millimeters
        spacing_mm: Spacing between QR codes in millimeters
        header_height_mm: Header height in millimeters
        min_qr_codes_per_page: Minimum QR codes that must fit per page (default: 4)

    Returns:
        Optimal QR code version (1-40)
    """
    # Try versions from largest (40) down to smallest (1)
    for version in range(40, 0, -1):
        qr_size = calculate_qr_physical_size(version, module_size_mm)
        rows, cols = calculate_grid_layout(page_width_mm, page_height_mm, qr_size,
                                          margin_mm, spacing_mm, header_height_mm)
        qr_codes_per_page = rows * cols

        # If this version fits at least the minimum, use it
        if qr_codes_per_page >= min_qr_codes_per_page:
            return version

    # Fallback to version 1 if nothing fits
    return 1


def get_qr_capacity(qr_version: int, error_correction: str) -> int:
    """Estimate maximum bytes that can fit in a QR code.

    This is an approximation. Actual capacity depends on data content.
    Binary mode capacities for different versions and error correction levels.

    Args:
        qr_version: QR code version (1-40)
        error_correction: Error correction level ('L', 'M', 'Q', 'H')

    Returns:
        Approximate capacity in bytes
    """
    # Simplified capacity table for binary mode
    # Format: {version: {error_level: bytes}}
    # Full table would be very long, so we use a formula approximation
    base_capacities = {
        1: {'L': 17, 'M': 14, 'Q': 11, 'H': 7},
        5: {'L': 108, 'M': 86, 'Q': 62, 'H': 46},
        10: {'L': 346, 'M': 271, 'Q': 213, 'H': 151},
        15: {'L': 682, 'M': 530, 'Q': 406, 'H': 304},
        20: {'L': 1085, 'M': 845, 'Q': 647, 'H': 485},
        25: {'L': 1596, 'M': 1258, 'Q': 938, 'H': 1046},
        30: {'L': 2306, 'M': 1628, 'Q': 1226, 'H': 904},
        40: {'L': 2953, 'M': 2331, 'Q': 1663, 'H': 1273},
    }

    # Find closest version in table
    if qr_version in base_capacities:
        return base_capacities[qr_version][error_correction]

    # Linear interpolation for versions not in table
    versions = sorted(base_capacities.keys())
    for i in range(len(versions) - 1):
        if versions[i] <= qr_version <= versions[i+1]:
            v1, v2 = versions[i], versions[i+1]
            c1 = base_capacities[v1][error_correction]
            c2 = base_capacities[v2][error_correction]
            # Linear interpolation
            ratio = (qr_version - v1) / (v2 - v1)
            return int(c1 + (c2 - c1) * ratio)

    # Fallback for version 1 or 40+
    if qr_version < 1:
        return base_capacities[1][error_correction]
    else:
        return base_capacities[40][error_correction]


def calculate_chunk_size(qr_version: int, error_correction: str) -> int:
    """Calculate optimal data chunk size per QR code.

    Accounts for JSON overhead and Base64 encoding.

    Args:
        qr_version: QR code version
        error_correction: Error correction level

    Returns:
        Bytes of raw data per QR code
    """
    qr_capacity = get_qr_capacity(qr_version, error_correction)

    # Account for JSON structure overhead (approximately 200-300 bytes)
    # and Base64 encoding overhead (4/3 expansion)
    json_overhead = 300
    usable_capacity = qr_capacity - json_overhead

    if usable_capacity <= 0:
        raise ValueError(f"QR version {qr_version} too small for metadata overhead")

    # Base64 encoding expands data by 4/3, so reverse that
    chunk_size = int(usable_capacity * 3 / 4)

    return max(chunk_size, 100)  # Minimum 100 bytes per chunk


def create_chunks(file_path: str, chunk_size: int, compression: str = 'bzip2',
                 encrypt: bool = False, password: Optional[str] = None,
                 argon2_time: int = 3, argon2_memory: int = 65536,
                 argon2_parallelism: int = 4,
                 parity_percent: float = 5.0) -> List[bytes]:
    """Split file into chunks with binary metadata headers, encryption, and parity support.

    Binary format (with encryption and parity support):
    - Page 1 (encrypted): [EncFlag:1][MD5:16][Page#:2][ParityFlag:1][FileSize:4][Salt:16][TimeCost:4][MemoryCost:4][Parallelism:4][VerifyHash:32][Nonce:12][Data]
    - Page 1 (unencrypted): [EncFlag:1][MD5:16][Page#:2][ParityFlag:1][FileSize:4][Data]
    - Other pages: [EncFlag:1][MD5:16][Page#:2][ParityFlag:1][Data]

    ParityFlag is always 0x00 for data pages (parity pages added separately)

    Args:
        file_path: Path to file to encode
        chunk_size: Size of each data chunk in bytes (before metadata)
        compression: Compression algorithm to use ('none', 'gzip', 'bzip2')
        encrypt: Enable encryption (default: False)
        password: Password for encryption (required if encrypt=True)
        argon2_time: Argon2 time cost (default: 3)
        argon2_memory: Argon2 memory cost in KB (default: 65536 = 64MB)
        argon2_parallelism: Argon2 parallelism (default: 4)
        parity_percent: Parity percentage (0-100). Default 5.0 = 5% overhead.
                       Set to 0 to disable parity. Parity pages = ceil(percent * data_pages)

    Returns:
        List of binary chunks including data chunks and parity chunks (if enabled)

    Raises:
        ValueError: If file size exceeds 2^32 bytes, page count exceeds 2^16, or encrypt=True but no password
    """
    # Read entire file
    with open(file_path, 'rb') as f:
        file_data = f.read()

    file_name = os.path.basename(file_path)
    file_size = len(file_data)

    # Check file size limit (2^32 bytes = 4GB)
    MAX_FILE_SIZE = 2**32
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File size {file_size:,} bytes exceeds maximum of {MAX_FILE_SIZE:,} bytes (2^32)")

    # Compress
    if compression != 'none':
        click.echo(f"Compressing with {compression}...")
        compressed_data = compress_data(file_data, compression)
        click.echo(f"  Original size: {file_size:,} bytes")
        click.echo(f"  Compressed size: {len(compressed_data):,} bytes ({len(compressed_data)/file_size*100:.1f}%)")
        data_to_chunk = compressed_data
    else:
        data_to_chunk = file_data

    # Optionally encrypt
    encryption_metadata = None
    if encrypt:
        if password is None:
            raise ValueError("Password required for encryption")

        click.echo("Encrypting...")
        enc_result = encrypt_data(
            data_to_chunk,
            password,
            time_cost=argon2_time,
            memory_cost=argon2_memory,
            parallelism=argon2_parallelism
        )
        data_to_chunk = enc_result['ciphertext']
        encryption_metadata = enc_result
        click.echo(f"Encrypted with AES-256-GCM (Argon2id: t={argon2_time}, m={argon2_memory}KB, p={argon2_parallelism})")

    # Calculate MD5 hash of (possibly encrypted) compressed data
    import hashlib
    file_md5 = hashlib.md5(data_to_chunk).digest()  # 16 bytes binary

    # Calculate total pages needed
    # Account for encryption flag (1 byte) and parity flag (1 byte) on all pages
    # Page 1 has: EncFlag(1) + MD5(16) + Page#(2) + ParityFlag(1) + FileSize(4) + [Encryption metadata if encrypted]
    if encrypt:
        # Encrypted page 1: + Salt(16) + TimeCost(4) + MemoryCost(4) + Parallelism(4) + VerifyHash(32) + Nonce(12) = 72 bytes
        page1_data_size = chunk_size - 96  # EncFlag(1) + MD5(16) + Page#(2) + ParityFlag(1) + FileSize(4) + EncMetadata(72)
    else:
        page1_data_size = chunk_size - 24  # EncFlag(1) + MD5(16) + Page#(2) + ParityFlag(1) + FileSize(4)

    # Other pages: EncFlag(1) + MD5(16) + Page#(2) + ParityFlag(1)
    other_page_data_size = chunk_size - 20

    if len(data_to_chunk) <= page1_data_size:
        # Fits in one page
        total_chunks = 1
    else:
        remaining = len(data_to_chunk) - page1_data_size
        total_chunks = 1 + ((remaining + other_page_data_size - 1) // other_page_data_size)

    # Check page count limit (2^16 pages = 65,536)
    MAX_PAGES = 2**16
    if total_chunks > MAX_PAGES:
        raise ValueError(f"File requires {total_chunks:,} pages, exceeds maximum of {MAX_PAGES:,} pages (2^16)")

    # Create chunks
    chunks = []
    offset = 0
    encryption_flag = 0x01 if encrypt else 0x00

    for page_num in range(1, total_chunks + 1):
        # Determine chunk size for this page
        if page_num == 1:
            this_chunk_size = page1_data_size
        else:
            this_chunk_size = other_page_data_size

        # Extract data for this chunk
        chunk_data = data_to_chunk[offset:offset + this_chunk_size]
        offset += len(chunk_data)

        # Build binary chunk
        chunk_binary = bytearray()

        # Encryption flag (1 byte)
        chunk_binary.append(encryption_flag)

        # MD5 hash (16 bytes)
        chunk_binary.extend(file_md5)

        # Page number (2 bytes, big-endian uint16)
        chunk_binary.extend(page_num.to_bytes(2, byteorder='big'))

        # Parity flag (1 byte) - 0x00 for data pages, 0x01 for parity pages
        chunk_binary.append(0x00)  # This is a data page

        # File size (4 bytes, big-endian uint32) - only on page 1
        if page_num == 1:
            chunk_binary.extend(file_size.to_bytes(4, byteorder='big'))

            # Encryption metadata (only on page 1 if encrypted)
            if encrypt:
                chunk_binary.extend(encryption_metadata['salt'])  # 16 bytes
                chunk_binary.extend(encryption_metadata['time_cost'].to_bytes(4, byteorder='big'))
                chunk_binary.extend(encryption_metadata['memory_cost'].to_bytes(4, byteorder='big'))
                chunk_binary.extend(encryption_metadata['parallelism'].to_bytes(4, byteorder='big'))
                chunk_binary.extend(encryption_metadata['verification_hash'])  # 32 bytes
                chunk_binary.extend(encryption_metadata['nonce'])  # 12 bytes

        # Data
        chunk_binary.extend(chunk_data)

        chunks.append(bytes(chunk_binary))

    # Generate parity pages (always enabled unless parity_percent = 0)
    num_parity = calculate_parity_count(len(chunks), parity_percent)

    if num_parity > 0:
        click.echo(f"Generating {num_parity} parity page(s)...")

        # Extract data portion from each chunk for parity calculation
        # We need to extract just the data payload (after all metadata)
        data_payloads = []
        for chunk in chunks:
            parsed = parse_binary_chunk(chunk)
            if parsed:
                data_payloads.append(parsed['data'])

        # Pad data payloads to same size
        padded_payloads, max_payload_size = pad_chunks(data_payloads)

        # Generate parity chunks
        parity_chunk_data = generate_parity_chunks(padded_payloads, num_parity)

        # Create parity page metadata and append to chunks
        for parity_idx, parity_data in enumerate(parity_chunk_data):
            page_num = len(chunks) + parity_idx + 1

            # Build parity chunk with metadata
            parity_chunk = bytearray()

            # Encryption flag (same as data pages)
            parity_chunk.append(encryption_flag)

            # MD5 hash (same as data pages - document-level MD5)
            parity_chunk.extend(file_md5)

            # Page number (continues from data pages)
            parity_chunk.extend(page_num.to_bytes(2, byteorder='big'))

            # Parity flag = 0x01 (this is a parity page)
            parity_chunk.append(0x01)

            # Parity metadata
            parity_chunk.extend(parity_idx.to_bytes(2, byteorder='big'))  # Parity index
            parity_chunk.extend(num_parity.to_bytes(2, byteorder='big'))  # Total parity pages
            parity_chunk.extend(len(chunks).to_bytes(2, byteorder='big'))  # Total data pages

            # Enhanced parity metadata (for page 1 recovery)
            compressed_size = len(data_to_chunk)  # Size before chunking
            parity_chunk.extend(compressed_size.to_bytes(4, byteorder='big'))  # Compressed size
            parity_chunk.extend(file_size.to_bytes(4, byteorder='big'))  # Original file size

            # If encrypted, include encryption metadata (needed to decrypt if page 1 missing)
            if encrypt:
                parity_chunk.extend(encryption_metadata['salt'])  # 16 bytes
                parity_chunk.extend(encryption_metadata['time_cost'].to_bytes(4, byteorder='big'))
                parity_chunk.extend(encryption_metadata['memory_cost'].to_bytes(4, byteorder='big'))
                parity_chunk.extend(encryption_metadata['parallelism'].to_bytes(4, byteorder='big'))
                parity_chunk.extend(encryption_metadata['verification_hash'])  # 32 bytes
                parity_chunk.extend(encryption_metadata['nonce'])  # 12 bytes

            # Parity data
            parity_chunk.extend(parity_data)

            chunks.append(bytes(parity_chunk))

        click.echo(f"  Total pages: {len(chunks)} ({len(chunks) - num_parity} data + {num_parity} parity)")

    return chunks


def create_qr_code(binary_data: bytes, qr_version: Optional[int],
                   error_correction: str, box_size: int = 10, border: int = 1) -> Image.Image:
    """Generate QR code image from binary data.

    Args:
        binary_data: Binary data to encode (will be base64 encoded)
        qr_version: QR code version (None for auto)
        error_correction: Error correction level
        box_size: Size of each QR code box in pixels
        border: Border size in boxes

    Returns:
        PIL Image of QR code
    """
    # Base64 encode binary data for QR code
    b64_data = base64.b64encode(binary_data).decode('ascii')

    # Create QR code
    qr = qrcode.QRCode(
        version=qr_version,
        error_correction=ERROR_CORRECTION_LEVELS[error_correction],
        box_size=box_size,
        border=border,
    )
    qr.add_data(b64_data)
    qr.make(fit=True)

    # Create image
    img = qr.make_image(fill_color="black", back_color="white")

    return img


def generate_pdf(qr_images: List[Image.Image], output_path: str, title: str,
                 page_width_mm: float, page_height_mm: float,
                 margin_mm: float, spacing_mm: float,
                 qrs_per_page: Tuple[int, int], qr_size_mm: float,
                 no_header: bool, total_pages: int,
                 chunks: Optional[List[bytes]] = None) -> None:
    """Create multi-page PDF from QR code images.

    Parity QR codes are placed on separate pages after all data QR codes.

    Args:
        qr_images: List of PIL Images of QR codes
        output_path: Path for output PDF
        title: Title for headers
        page_width_mm: Page width in millimeters
        page_height_mm: Page height in millimeters
        margin_mm: Page margin in millimeters
        spacing_mm: Spacing between QR codes in millimeters
        qrs_per_page: Tuple of (rows, cols)
        qr_size_mm: Size of each QR code in millimeters
        no_header: Skip header if True
        total_pages: Total number of pages for header
        chunks: Optional list of binary chunks (for parity detection)
    """
    # Convert mm to points (ReportLab uses points)
    page_width = page_width_mm * mm
    page_height = page_height_mm * mm
    margin = margin_mm * mm
    spacing = spacing_mm * mm
    qr_size = qr_size_mm * mm

    c = pdf_canvas.Canvas(output_path, pagesize=(page_width, page_height))

    rows, cols = qrs_per_page
    qrs_on_page = rows * cols

    header_height = 40 * mm if not no_header else 0

    # Find first parity QR index (if any)
    first_parity_idx = None
    if chunks:
        for idx, chunk in enumerate(chunks):
            parsed = parse_binary_chunk(chunk)
            if parsed and parsed.get('is_parity'):
                first_parity_idx = idx
                break

    # Separate data and parity QR images
    if first_parity_idx is not None:
        data_qr_images = qr_images[:first_parity_idx]
        parity_qr_images = qr_images[first_parity_idx:]
    else:
        data_qr_images = qr_images
        parity_qr_images = []

    # Calculate pages needed
    data_pages = (len(data_qr_images) + qrs_on_page - 1) // qrs_on_page if data_qr_images else 0
    parity_pages = (len(parity_qr_images) + qrs_on_page - 1) // qrs_on_page if parity_qr_images else 0
    total_pdf_pages = data_pages + parity_pages

    # Calculate horizontal centering offset
    grid_width = cols * qr_size + (cols - 1) * spacing
    available_width = page_width - 2 * margin
    horizontal_offset = (available_width - grid_width) / 2

    # Generate data pages
    for page_idx in range(data_pages):
        # Draw header
        if not no_header:
            c.setFont("Helvetica-Bold", 14)
            c.drawString(margin, page_height - margin - 5*mm, "QR Code Backup Archive")

            c.setFont("Helvetica", 10)
            c.drawString(margin, page_height - margin - 12*mm, f"Title: {title}")
            c.drawString(margin, page_height - margin - 18*mm,
                        f"Page {page_idx + 1} of {total_pdf_pages}")
            c.drawString(margin, page_height - margin - 24*mm,
                        "Decode with: qr_code_backup decode")

            # Draw line
            c.line(margin, page_height - margin - 28*mm,
                  page_width - margin, page_height - margin - 28*mm)

        # Draw data QR codes in grid
        start_idx = page_idx * qrs_on_page
        end_idx = min(start_idx + qrs_on_page, len(data_qr_images))

        for local_idx, qr_idx in enumerate(range(start_idx, end_idx)):
            row = local_idx // cols
            col = local_idx % cols

            x = margin + horizontal_offset + col * (qr_size + spacing)
            y = page_height - header_height - margin - (row + 1) * qr_size - row * spacing

            # Save QR image to temporary buffer
            img_buffer = io.BytesIO()
            data_qr_images[qr_idx].save(img_buffer, format='PNG')
            img_buffer.seek(0)

            # Draw on PDF using ImageReader
            c.drawImage(ImageReader(img_buffer), x, y, width=qr_size, height=qr_size)

        c.showPage()

    # Generate parity pages (on separate pages after data)
    for parity_page_idx in range(parity_pages):
        pdf_page_idx = data_pages + parity_page_idx

        # Draw header
        if not no_header:
            c.setFont("Helvetica-Bold", 14)
            c.drawString(margin, page_height - margin - 5*mm, "QR Code Backup Archive")

            c.setFont("Helvetica", 10)
            c.drawString(margin, page_height - margin - 12*mm, f"Title: {title}")
            c.drawString(margin, page_height - margin - 18*mm,
                        f"Page {pdf_page_idx + 1} of {total_pdf_pages}")
            c.drawString(margin, page_height - margin - 24*mm,
                        "Decode with: qr_code_backup decode")

            # Draw line
            c.line(margin, page_height - margin - 28*mm,
                  page_width - margin, page_height - margin - 28*mm)

        # Draw parity QR codes in grid
        start_idx = parity_page_idx * qrs_on_page
        end_idx = min(start_idx + qrs_on_page, len(parity_qr_images))

        for local_idx, qr_idx in enumerate(range(start_idx, end_idx)):
            row = local_idx // cols
            col = local_idx % cols

            x = margin + horizontal_offset + col * (qr_size + spacing)
            y = page_height - header_height - margin - (row + 1) * qr_size - row * spacing

            # Save QR image to temporary buffer
            img_buffer = io.BytesIO()
            parity_qr_images[qr_idx].save(img_buffer, format='PNG')
            img_buffer.seek(0)

            # Draw on PDF using ImageReader
            c.drawImage(ImageReader(img_buffer), x, y, width=qr_size, height=qr_size)

            # Label parity pages
            if chunks and not no_header:
                chunk_idx = first_parity_idx + qr_idx
                parsed = parse_binary_chunk(chunks[chunk_idx])
                if parsed and parsed.get('is_parity'):
                    # Draw "PARITY" label below QR code
                    c.setFont("Helvetica-Bold", 8)
                    label_y = y - 8
                    c.drawCentredString(x + qr_size/2, label_y,
                                       f"PARITY {parsed['parity_index']+1}/{parsed['total_parity']}")

        c.showPage()

    c.save()


# ============================================================================
# DECODING FUNCTIONS
# ============================================================================

def pdf_to_images(pdf_path: str) -> List[np.ndarray]:
    """Convert PDF pages to OpenCV images.

    Args:
        pdf_path: Path to PDF file

    Returns:
        List of images as numpy arrays (OpenCV format)
    """
    from pdf2image import convert_from_path

    # Convert PDF to PIL images
    pil_images = convert_from_path(pdf_path, dpi=300)

    # Convert to OpenCV format (numpy arrays)
    cv_images = []
    for pil_img in pil_images:
        # Convert PIL to numpy array (RGB)
        img_array = np.array(pil_img)
        # Convert RGB to BGR for OpenCV
        img_bgr = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
        cv_images.append(img_bgr)

    return cv_images


def decode_qr_codes_from_image(image: np.ndarray) -> List[bytes]:
    """Find and decode all QR codes in an image.

    Args:
        image: OpenCV image (numpy array)

    Returns:
        List of binary chunks (base64 decoded)
    """
    # Convert to grayscale for better detection
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Detect and decode QR codes
    decoded_objects = pyzbar.decode(gray)

    results = []
    for obj in decoded_objects:
        # Decode base64 data to binary
        try:
            b64_string = obj.data.decode('utf-8')
            binary_data = base64.b64decode(b64_string)
            results.append(binary_data)
        except Exception:
            # Skip invalid QR codes
            continue

    return results


def parse_binary_chunk(chunk_binary: bytes) -> Optional[Dict[str, Any]]:
    """Parse binary chunk header with encryption and parity support.

    Binary format (with encryption and parity support):
    - Data page 1 (encrypted): [EncFlag:1][MD5:16][Page#:2][ParityFlag:1][FileSize:4][Salt:16][TimeCost:4][MemoryCost:4][Parallelism:4][VerifyHash:32][Nonce:12][Data]
    - Data page 1 (unencrypted): [EncFlag:1][MD5:16][Page#:2][ParityFlag:1][FileSize:4][Data]
    - Data page N (encrypted): [EncFlag:1][MD5:16][Page#:2][ParityFlag:1][Data]
    - Data page N (unencrypted): [EncFlag:1][MD5:16][Page#:2][ParityFlag:1][Data]
    - Parity page (unencrypted): [EncFlag:1][MD5:16][Page#:2][ParityFlag:1][ParityIdx:2][TotalParity:2][TotalData:2][CompressedSize:4][FileSize:4][ParityData]
    - Parity page (encrypted): [EncFlag:1][MD5:16][Page#:2][ParityFlag:1][ParityIdx:2][TotalParity:2][TotalData:2][CompressedSize:4][FileSize:4][Salt:16][TimeCost:4][MemoryCost:4][Parallelism:4][VerifyHash:32][Nonce:12][ParityData]

    Encryption Flag: 0x00 = unencrypted, 0x01 = encrypted
    Parity Flag: 0x00 = data page, 0x01 = parity page

    Args:
        chunk_binary: Binary chunk data

    Returns:
        Dictionary with parsed metadata, or None if invalid
    """
    try:
        offset = 0

        # Minimum size check: EncFlag(1) + MD5(16) + Page#(2) + ParityFlag(1) = 20 bytes
        if len(chunk_binary) < 20:
            return None

        # Extract encryption flag (1 byte)
        encrypted = chunk_binary[offset] != 0x00
        offset += 1

        # Extract MD5 hash (16 bytes)
        md5_hash = chunk_binary[offset:offset+16]
        offset += 16

        # Extract page number (2 bytes, big-endian uint16)
        page_num = int.from_bytes(chunk_binary[offset:offset+2], byteorder='big')
        offset += 2

        # Extract parity flag (1 byte)
        is_parity = chunk_binary[offset] != 0x00
        offset += 1

        result = {
            'encrypted': encrypted,
            'md5_hash': md5_hash,
            'page_number': page_num,
            'is_parity': is_parity,
        }

        if is_parity:
            # Parity page: ParityIdx(2) + TotalParity(2) + TotalData(2) + CompressedSize(4) + FileSize(4) = 14 bytes minimum
            if len(chunk_binary) < offset + 14:
                return None

            result['parity_index'] = int.from_bytes(chunk_binary[offset:offset+2], byteorder='big')
            offset += 2
            result['total_parity'] = int.from_bytes(chunk_binary[offset:offset+2], byteorder='big')
            offset += 2
            result['total_data'] = int.from_bytes(chunk_binary[offset:offset+2], byteorder='big')
            offset += 2

            # Enhanced parity metadata (for page 1 recovery)
            result['compressed_size'] = int.from_bytes(chunk_binary[offset:offset+4], byteorder='big')
            offset += 4
            result['file_size'] = int.from_bytes(chunk_binary[offset:offset+4], byteorder='big')
            offset += 4

            # If encrypted, parse encryption metadata
            if encrypted:
                # Need encryption metadata: Salt(16) + TimeCost(4) + MemoryCost(4) + Parallelism(4) + VerifyHash(32) + Nonce(12) = 72 bytes
                if len(chunk_binary) < offset + 72:
                    return None

                result['salt'] = chunk_binary[offset:offset+16]
                offset += 16
                result['time_cost'] = int.from_bytes(chunk_binary[offset:offset+4], byteorder='big')
                offset += 4
                result['memory_cost'] = int.from_bytes(chunk_binary[offset:offset+4], byteorder='big')
                offset += 4
                result['parallelism'] = int.from_bytes(chunk_binary[offset:offset+4], byteorder='big')
                offset += 4
                result['verification_hash'] = chunk_binary[offset:offset+32]
                offset += 32
                result['nonce'] = chunk_binary[offset:offset+12]
                offset += 12
        else:
            # Data page: Page 1 has file size and possibly encryption metadata
            if page_num == 1:
                # Need at least file size (4 bytes)
                if len(chunk_binary) < offset + 4:
                    return None

                file_size = int.from_bytes(chunk_binary[offset:offset+4], byteorder='big')
                offset += 4
                result['file_size'] = file_size

                if encrypted:
                    # Need encryption metadata: Salt(16) + TimeCost(4) + MemoryCost(4) + Parallelism(4) + VerifyHash(32) + Nonce(12) = 72 bytes
                    if len(chunk_binary) < offset + 72:
                        return None

                    result['salt'] = chunk_binary[offset:offset+16]
                    offset += 16
                    result['time_cost'] = int.from_bytes(chunk_binary[offset:offset+4], byteorder='big')
                    offset += 4
                    result['memory_cost'] = int.from_bytes(chunk_binary[offset:offset+4], byteorder='big')
                    offset += 4
                    result['parallelism'] = int.from_bytes(chunk_binary[offset:offset+4], byteorder='big')
                    offset += 4
                    result['verification_hash'] = chunk_binary[offset:offset+32]
                    offset += 32
                    result['nonce'] = chunk_binary[offset:offset+12]
                    offset += 12
            else:
                result['file_size'] = None

        # Data is everything after metadata
        result['data'] = chunk_binary[offset:]

        return result
    except Exception:
        return None


def reassemble_chunks(chunk_binaries: List[bytes], verify: bool = True,
                     recovery_mode: bool = False,
                     password: Optional[str] = None) -> Tuple[bytes, Dict[str, Any]]:
    """Sort, validate, and reassemble binary chunks into original file with decryption support.

    Validates:
    - All chunks have the same MD5 hash (detects mixed documents)
    - Page sequence is correct (1, 2, 3, ... N with no gaps or wrong order)
    - Decrypts data if encrypted (requires password)
    - Final decompressed data matches MD5 hash from chunks

    Args:
        chunk_binaries: List of binary chunk data
        verify: Verify MD5 consistency and sequence if True
        recovery_mode: Attempt recovery even with missing chunks or errors
        password: Password for decryption (required if chunks are encrypted)

    Returns:
        Tuple of (file_data, report_dict)

    Raises:
        ValueError: If chunks cannot be reassembled, validation fails, or encrypted but no password
    """
    if not chunk_binaries:
        raise ValueError("No chunks provided")

    # Parse all chunks
    parsed_chunks = []
    for i, chunk_binary in enumerate(chunk_binaries):
        parsed = parse_binary_chunk(chunk_binary)
        if parsed is None:
            if not recovery_mode:
                raise ValueError(f"Failed to parse chunk {i+1}")
            continue
        parsed_chunks.append(parsed)

    if not parsed_chunks:
        raise ValueError("No valid chunks found")

    # Sort by page number
    parsed_chunks.sort(key=lambda x: x['page_number'])

    # Separate data chunks and parity chunks
    data_chunks = [c for c in parsed_chunks if not c.get('is_parity', False)]
    parity_chunks = [c for c in parsed_chunks if c.get('is_parity', False)]

    # Get reference MD5 from first chunk
    reference_md5 = parsed_chunks[0]['md5_hash']

    # Validate MD5 consistency across all pages
    if verify:
        md5_mismatches = []
        for chunk in parsed_chunks:
            if chunk['md5_hash'] != reference_md5:
                md5_mismatches.append(chunk['page_number'])

        if md5_mismatches:
            raise ValueError(
                f"Mixed documents detected! Pages {md5_mismatches} have different MD5 hashes. "
                f"All pages must be from the same backup file."
            )

    # Get file size and total pages from page 1 (if available)
    page_1 = None
    for chunk in data_chunks:  # Look in data_chunks, not all chunks
        if chunk['page_number'] == 1:
            page_1 = chunk
            break

    # Validate page sequence
    data_page_numbers = [c['page_number'] for c in data_chunks]

    # Check for duplicates
    if len(data_page_numbers) != len(set(data_page_numbers)):
        duplicates = [p for p in data_page_numbers if data_page_numbers.count(p) > 1]
        raise ValueError(f"Duplicate pages detected: {list(set(duplicates))}")

    # If we have parity chunks, check for missing data pages (including page 1)
    if parity_chunks:
        click.echo(f"Found {len(parity_chunks)} parity page(s)")

        # Get expected data pages from parity metadata
        expected_data_pages = parity_chunks[0]['total_data']

        # Find missing data pages
        expected_data_set = set(range(1, expected_data_pages + 1))
        actual_data_set = set(data_page_numbers)
        missing_data_pages = sorted(expected_data_set - actual_data_set)

        if missing_data_pages:
            click.echo(f"Missing {len(missing_data_pages)} data page(s): {missing_data_pages}")
            click.echo("Attempting parity recovery...")

            # Check if we can recover
            num_parity = len(parity_chunks)
            if len(missing_data_pages) > num_parity:
                raise ValueError(
                    f"Cannot recover: {len(missing_data_pages)} pages missing "
                    f"but only {num_parity} parity pages available"
                )

            # Build list with None for missing data pages
            all_data_with_gaps = [None] * expected_data_pages
            for chunk in data_chunks:
                all_data_with_gaps[chunk['page_number'] - 1] = chunk['data']

            # Extract parity data (sorted by parity index)
            parity_chunks_sorted = sorted(parity_chunks, key=lambda x: x['parity_index'])
            parity_data = [c['data'] for c in parity_chunks_sorted]

            # Pad existing data chunks to match parity data size
            # (parity data was generated from padded chunks)
            parity_size = len(parity_data[0])
            for i in range(len(all_data_with_gaps)):
                if all_data_with_gaps[i] is not None and len(all_data_with_gaps[i]) < parity_size:
                    # Pad to match parity size
                    all_data_with_gaps[i] = all_data_with_gaps[i] + b'\x00' * (parity_size - len(all_data_with_gaps[i]))

            # Recover missing chunks
            try:
                recovered_data = recover_missing_chunks(
                    all_data_with_gaps,
                    parity_data,
                    expected_data_pages
                )

                # Get encryption flag from any available chunk (all pages have same flag)
                encryption_flag = parsed_chunks[0]['encrypted'] if parsed_chunks else False

                # Compute chunk data capacities from chunk_size and metadata overhead
                # Get chunk_size from any chunk binary (they're all the same size)
                reference_chunk_binary = chunk_binaries[0]
                chunk_size = len(reference_chunk_binary)

                # Calculate data capacities based on metadata overhead
                # Page 1 has extra metadata (file_size + possibly encryption metadata)
                if encryption_flag:
                    page1_data_capacity = chunk_size - 96  # EncFlag(1) + MD5(16) + Page#(2) + ParityFlag(1) + FileSize(4) + EncMeta(72)
                    other_data_capacity = chunk_size - 20  # EncFlag(1) + MD5(16) + Page#(2) + ParityFlag(1)
                else:
                    page1_data_capacity = chunk_size - 24  # EncFlag(1) + MD5(16) + Page#(2) + ParityFlag(1) + FileSize(4)
                    other_data_capacity = chunk_size - 20  # EncFlag(1) + MD5(16) + Page#(2) + ParityFlag(1)

                # Reconstruct data_chunks with recovered pages
                # Calculate actual size for each chunk based on compressed_size
                data_chunks = []
                compressed_size_val = parity_chunks[0]['compressed_size']
                bytes_so_far = 0

                for page_num, data in enumerate(recovered_data, 1):
                    # Find original chunk if it exists
                    original_chunk = next((c for c in parsed_chunks if c['page_number'] == page_num and not c.get('is_parity')), None)

                    if original_chunk:
                        # Use original chunk (already has correct size, no padding)
                        data_chunks.append(original_chunk)
                        bytes_so_far += len(original_chunk['data'])
                    else:
                        # Recovered chunk - need to strip padding
                        # Determine capacity for this chunk
                        if page_num == 1:
                            capacity = page1_data_capacity
                        else:
                            capacity = other_data_capacity

                        # Actual size is min of capacity and remaining bytes
                        remaining = compressed_size_val - bytes_so_far
                        actual_size = min(capacity, remaining)

                        # Strip padding from recovered data
                        recovered_chunk_data = data[:actual_size]
                        bytes_so_far += actual_size

                        # Create reconstructed chunk metadata for recovered page
                        data_chunks.append({
                            'page_number': page_num,
                            'md5_hash': reference_md5,
                            'data': recovered_chunk_data,
                            'encrypted': encryption_flag,
                            'file_size': None,  # Will be set below for page 1
                            'is_parity': False,
                        })

                # Re-sort after recovery
                data_chunks.sort(key=lambda x: x['page_number'])
                data_page_numbers = [c['page_number'] for c in data_chunks]

                # Update page_1 reference after recovery
                page_1 = None
                for chunk in data_chunks:
                    if chunk['page_number'] == 1:
                        page_1 = chunk
                        break

                # If page 1 was recovered, populate metadata from parity chunks
                if page_1 and page_1['file_size'] is None and 1 in missing_data_pages:
                    # Use metadata from parity chunks
                    page_1['file_size'] = parity_chunks[0]['file_size']
                    if encryption_flag:
                        # Copy encryption metadata from parity chunks
                        page_1['salt'] = parity_chunks[0]['salt']
                        page_1['nonce'] = parity_chunks[0]['nonce']
                        page_1['verification_hash'] = parity_chunks[0]['verification_hash']
                        page_1['time_cost'] = parity_chunks[0]['time_cost']
                        page_1['memory_cost'] = parity_chunks[0]['memory_cost']
                        page_1['parallelism'] = parity_chunks[0]['parallelism']

                click.echo(f"Successfully recovered {len(missing_data_pages)} page(s)!")

                report = {
                    'found_pages': len(data_chunks),
                    'missing_pages': [],
                    'parity_recovery': len(missing_data_pages),
                    'md5_hash': reference_md5.hex(),
                    'file_size': page_1['file_size'] if page_1 else parity_chunks[0]['file_size'],
                    'compressed_size': parity_chunks[0]['compressed_size'],  # Track for padding removal
                }
            except ValueError as e:
                raise ValueError(f"Parity recovery failed: {e}")
        else:
            click.echo("No missing pages, parity recovery not needed")
            report = {
                'found_pages': len(data_chunks),
                'missing_pages': [],
                'parity_recovery': 0,
                'md5_hash': reference_md5.hex(),
                'file_size': page_1['file_size'] if page_1 else None,
            }
    else:
        # No parity chunks - page 1 is required
        if page_1 is None:
            raise ValueError("Page 1 not found - cannot determine file size")

        # Use original validation logic
        max_page = max(data_page_numbers)
        expected_pages = set(range(1, max_page + 1))
        actual_pages = set(data_page_numbers)
        missing_pages = sorted(expected_pages - actual_pages)

        report = {
            'found_pages': len(actual_pages),
            'missing_pages': missing_pages,
            'md5_hash': reference_md5.hex(),
            'file_size': page_1['file_size'],
        }

        # Check for missing pages in sequence
        if verify and missing_pages and not recovery_mode:
            raise ValueError(
                f"Missing pages in sequence: {missing_pages}. "
                f"Found pages {sorted(data_page_numbers)}. "
                f"All pages from 1 to {max_page} must be present."
            )

    # Reassemble compressed (possibly encrypted) data from data chunks only
    # Note: Padding has already been stripped per-chunk during recovery
    compressed_data = b''
    for chunk in data_chunks:
        compressed_data += chunk['data']

    # Verify MD5 BEFORE decryption (MD5 is of encrypted data if encrypted)
    if verify:
        actual_md5 = hashlib.md5(compressed_data).digest()
        if actual_md5 != reference_md5:
            raise ValueError(
                f"MD5 verification failed! "
                f"Expected: {reference_md5.hex()}, "
                f"Got: {actual_md5.hex()}. "
                f"Data corruption detected."
            )
        report['md5_verified'] = True

    # Check if encrypted and decrypt if needed
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
            click.echo("Decryption successful")
        except ValueError as e:
            raise ValueError(f"Decryption failed: {e}")
        except Exception as e:
            raise ValueError(f"Decryption failed - data may be corrupted: {e}")

    # Decompress (hardcoded bzip2)
    try:
        file_data = decompress_data(compressed_data, 'bzip2')
    except Exception as e:
        if not recovery_mode:
            raise ValueError(f"Decompression failed: {e}")
        # In recovery mode, return compressed data
        file_data = compressed_data
        report['decompression_failed'] = True

    report['recovered_size'] = len(file_data)
    report['compression'] = 'bzip2'

    return file_data, report


# ============================================================================
# CLI COMMANDS
# ============================================================================

@click.group()
@click.version_option(version=VERSION)
def cli():
    """QR Code Backup - Archive data as printable QR codes for offline storage.

    This tool encodes files into multi-page PDF documents containing QR codes,
    and can decode scanned PDFs back into the original files.
    """
    pass


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), default=None,
              help='Output PDF path (default: <input_file>.qr.pdf)')
@click.option('--error-correction', type=click.Choice(['L', 'M', 'Q', 'H']), default='M',
              help='Error correction level: L(7%), M(15%), Q(25%), H(30%) [default: M]')
@click.option('--density', type=float, default=0.8,
              help='QR code density in mm (smaller = denser). [default: 0.8]')
@click.option('--title', type=str, default=None,
              help='Title for page headers (default: filename)')
@click.option('--encrypt', is_flag=True,
              help='Encrypt the data before encoding (prompts for password)')
@click.option('--parity-percent', type=float, default=5.0,
              help='Parity percentage for recovery (0-100). Default 5.0 = 5%% overhead. Set to 0 to disable.')
def encode(input_file, output, error_correction, density, title, encrypt, parity_percent):
    """Encode a file into a QR code backup PDF.

    Example:
        qr_code_backup encode mydata.txt -o backup.pdf
        qr_code_backup encode secret.txt -o backup.pdf --encrypt
    """
    try:
        # Hardcoded defaults (opinionated choices like tar)
        compression = 'bzip2'
        page_width = 215.9  # US Letter
        page_height = 279.4
        margin = 20.0
        spacing = 5.0
        header_height = 40.0
        argon2_time = 3
        argon2_memory = 65536  # 64MB
        argon2_parallelism = 4

        # Handle encryption password
        password = None
        if encrypt:
            password = click.prompt('Enter encryption password', hide_input=True, confirmation_prompt=True)
            click.echo(f"Encryption: AES-256-GCM with Argon2id")

        # Validate density and warn if too small
        if density < 0.8:
            click.echo(f"\nWARNING: Density {density}mm is below recommended minimum (0.8mm).", err=True)
            click.echo(f"         This density risks data loss when printed and scanned.", err=True)
            click.echo(f"         Consider using --density 1.2 or higher for reliable results.\n", err=True)

        # Set defaults
        if output is None:
            output = input_file + '.qr.pdf'
        if title is None:
            title = os.path.basename(input_file)

        # Auto-calculate optimal QR version for 2x2 grid (4 codes per page)
        optimal_version = calculate_optimal_qr_version(
            density, page_width, page_height, margin, spacing, header_height,
            min_qr_codes_per_page=4
        )

        # Calculate QR code physical size
        qr_physical_size = calculate_qr_physical_size(optimal_version, density)

        # Calculate grid layout
        rows, cols = calculate_grid_layout(page_width, page_height, qr_physical_size,
                                           margin, spacing, header_height)
        qrs_per_page = rows * cols

        # Display configuration
        click.echo(f"\nEncoding: {input_file}")
        if encrypt:
            click.echo(f"Encryption: Enabled (AES-256-GCM)")
        click.echo(f"QR Configuration: Version {optimal_version}, Error Correction {error_correction}, Density {density}mm")
        click.echo(f"Grid Layout: {rows} rows × {cols} columns = {qrs_per_page} QR codes per page")

        # Calculate chunk size
        chunk_size = calculate_chunk_size(optimal_version, error_correction)

        # Create chunks (returns list of binary data)
        # Parity is always enabled by default (5%) unless user sets parity_percent=0
        click.echo(f"Chunk size: {chunk_size:,} bytes per QR code")
        if parity_percent > 0:
            click.echo(f"Parity: {parity_percent}% overhead")
        else:
            click.echo(f"Parity: Disabled")
        if encrypt:
            click.echo("Compressing and encrypting...")
        chunks = create_chunks(input_file, chunk_size, compression,
                              encrypt=encrypt, password=password,
                              argon2_time=argon2_time,
                              argon2_memory=argon2_memory,
                              argon2_parallelism=argon2_parallelism,
                              parity_percent=parity_percent)

        # Extract MD5 from first chunk for display (bytes 1-17, after encryption flag)
        file_md5_binary = chunks[0][1:17]
        file_md5_hex = file_md5_binary.hex()

        # Calculate number of pages needed
        num_pages = (len(chunks) + qrs_per_page - 1) // qrs_per_page
        click.echo(f"QR codes required: {len(chunks)}")
        click.echo(f"PDF pages required: {num_pages}")

        # Generate QR codes
        click.echo("Generating QR codes...")
        qr_images = []
        with click.progressbar(chunks, label='Creating QR codes') as bar:
            for chunk_binary in bar:
                img = create_qr_code(chunk_binary, optimal_version, error_correction)
                qr_images.append(img)

        # Generate PDF
        click.echo("Writing PDF...")
        generate_pdf(qr_images, output, title, page_width, page_height,
                    margin, spacing, (rows, cols), qr_physical_size, False, len(chunks),
                    chunks=chunks)

        # Display summary
        click.echo(f"\nOutput: {output}")
        click.echo(f"Verification hash (MD5): {file_md5_hex}")
        click.echo(f"Store this hash separately to verify successful recovery.")

    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('input_pdf', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), required=True,
              help='Output file path (required)')
@click.option('--verify', is_flag=True, default=True,
              help='Verify integrity using checksums [default: enabled]')
@click.option('--recovery-mode', is_flag=True,
              help='Attempt recovery from missing/damaged QR codes')
@click.option('--force', is_flag=True,
              help='Overwrite existing output file')
@click.option('--password', type=str, default=None,
              help='Decryption password (will prompt if encrypted and not provided)')
def decode(input_pdf, output, verify, recovery_mode, force, password):
    """Decode a QR code backup PDF into original file.

    Example:
        qr_code_backup decode backup.pdf -o recovered.txt
        qr_code_backup decode encrypted_backup.pdf -o recovered.txt --password mypass
    """
    try:
        click.echo(f"\nDecoding: {input_pdf}")

        # Convert PDF to images
        click.echo("Converting PDF to images...")
        images = pdf_to_images(input_pdf)
        click.echo(f"Found {len(images)} pages")

        # Decode QR codes from all pages with MD5 validation (returns list of binary chunks)
        click.echo("Reading QR codes...")
        all_chunk_binaries = []
        qr_count = 0
        reference_md5 = None
        reference_page_num = None

        with click.progressbar(images, label='Scanning pages') as bar:
            for pdf_page_idx, image in enumerate(bar, 1):
                chunk_binaries = decode_qr_codes_from_image(image)

                for chunk_binary in chunk_binaries:
                    # Parse to check MD5 (immediate mixed document detection)
                    parsed = parse_binary_chunk(chunk_binary)

                    if parsed is None:
                        click.echo(f"\nWarning: PDF page {pdf_page_idx} - Failed to parse QR code", err=True)
                        continue

                    # Establish reference MD5 from first valid chunk
                    if reference_md5 is None:
                        reference_md5 = parsed['md5_hash']
                        reference_page_num = parsed['page_number']
                        click.echo(f"\nDocument MD5: {reference_md5.hex()}")
                    else:
                        # Check MD5 consistency (detect mixed documents immediately)
                        if parsed['md5_hash'] != reference_md5:
                            raise click.ClickException(
                                f"\n{'='*60}\n"
                                f"ERROR: PDF page {pdf_page_idx} contains QR code from a different document!\n\n"
                                f"Expected MD5 (from QR page {reference_page_num}): {reference_md5.hex()}\n"
                                f"Found MD5 (QR page {parsed['page_number']}):       {parsed['md5_hash'].hex()}\n\n"
                                f"This PDF contains pages from multiple QR code backups.\n"
                                f"Please ensure all PDF pages are from the same backup before decoding.\n"
                                f"{'='*60}"
                            )

                    all_chunk_binaries.append(chunk_binary)
                    qr_count += 1

        click.echo(f"Successfully decoded {qr_count} QR codes from {len(images)} PDF pages")

        if not all_chunk_binaries:
            click.echo("Error: No valid QR codes found", err=True)
            sys.exit(1)

        # Analyze page order (order-independent decoding feedback)
        click.echo("\nAnalyzing decoded pages...")
        parsed_for_analysis = []
        for chunk_binary in all_chunk_binaries:
            parsed = parse_binary_chunk(chunk_binary)
            if parsed:
                parsed_for_analysis.append(parsed)

        if parsed_for_analysis:
            page_numbers_sorted = sorted([p['page_number'] for p in parsed_for_analysis])
            scan_order = [p['page_number'] for p in parsed_for_analysis]

            click.echo(f"Detected QR pages: {page_numbers_sorted}")

            # Check if pages were scanned out of order
            if scan_order != page_numbers_sorted:
                click.echo("Pages were scanned out of order - reordering automatically...")

            # Check for encryption and prompt for password if needed
            first_chunk = next((p for p in parsed_for_analysis if p['page_number'] == 1), None)
            if first_chunk and first_chunk.get('encrypted'):
                click.echo("\nDocument is encrypted (AES-256-GCM)")
                if password is None:
                    password = click.prompt('Enter decryption password', hide_input=True)

        # Reassemble file
        click.echo("Reassembling data...")
        try:
            file_data, report = reassemble_chunks(all_chunk_binaries, verify=verify,
                                                 recovery_mode=recovery_mode,
                                                 password=password)
        except ValueError as e:
            click.echo(f"\nError: {e}", err=True)
            if not recovery_mode:
                click.echo("Use --recovery-mode to attempt partial recovery", err=True)
            sys.exit(1)

        # Check if file exists
        if os.path.exists(output) and not force:
            click.echo(f"\nError: Output file '{output}' already exists. Use --force to overwrite.", err=True)
            sys.exit(1)

        # Write output
        click.echo(f"Decompressing..." if report['compression'] == 'bzip2' else "Writing output...")
        with open(output, 'wb') as f:
            f.write(file_data)

        # Display report
        click.echo(f"\nRecovered: {output} ({report['recovered_size']:,} bytes)")
        click.echo(f"Original file size: {report['file_size']:,} bytes")

        if report.get('decryption') == 'success':
            click.echo("Decryption: SUCCESS")

        if verify:
            if report.get('md5_verified'):
                click.echo(f"Verification: PASS (MD5: {report['md5_hash']})")
            elif report.get('decompression_failed'):
                click.echo("Warning: Decompression failed - output may be corrupted!", err=True)
            else:
                click.echo("Verification: Skipped")

        if report['missing_pages']:
            click.echo(f"Warning: Missing {len(report['missing_pages'])} pages: {report['missing_pages']}", err=True)

    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument('pdf_file', type=click.Path(exists=True))
def info(pdf_file):
    """Display metadata about a QR code backup PDF.

    Example:
        qr_code_backup info backup.pdf
    """
    try:
        click.echo(f"\nReading: {pdf_file}")

        # Convert first page to image
        images = pdf_to_images(pdf_file)
        if not images:
            click.echo("Error: No pages found in PDF", err=True)
            sys.exit(1)

        # Decode QR codes from first page (returns binary chunks)
        chunk_binaries = decode_qr_codes_from_image(images[0])

        if not chunk_binaries:
            click.echo("Error: No QR codes found on first page", err=True)
            sys.exit(1)

        # Parse first QR code (should be page 1)
        metadata = parse_binary_chunk(chunk_binaries[0])

        if not metadata:
            click.echo("Error: Failed to parse QR code metadata", err=True)
            sys.exit(1)

        # Count total QR codes and detect parity pages
        total_qr_codes = 0
        data_pages = 0
        parity_pages = 0
        parity_info = None

        for image in images:
            qr_binaries = decode_qr_codes_from_image(image)
            total_qr_codes += len(qr_binaries)

            # Check for parity pages
            for qr_bin in qr_binaries:
                parsed = parse_binary_chunk(qr_bin)
                if parsed:
                    if parsed.get('is_parity'):
                        parity_pages += 1
                        if parity_info is None:
                            parity_info = parsed
                    else:
                        data_pages += 1

        # Display metadata
        click.echo(f"\n{'='*60}")
        click.echo("QR CODE BACKUP METADATA")
        click.echo(f"{'='*60}")
        click.echo(f"Format Version:      Binary v1.0")
        click.echo(f"Encryption:          {'Yes (AES-256-GCM)' if metadata.get('encrypted') else 'No'}")
        if metadata.get('encrypted') and metadata.get('time_cost'):
            click.echo(f"Argon2 Parameters:   time={metadata['time_cost']}, memory={metadata['memory_cost']}KiB, parallelism={metadata['parallelism']}")
        click.echo(f"Original File Size:  {metadata.get('file_size', 'N/A'):,} bytes" if metadata.get('file_size') else "Original File Size:  N/A (not page 1)")
        click.echo(f"MD5 Hash:            {metadata['md5_hash'].hex()}")
        click.echo(f"Page Number:         {metadata['page_number']}")
        click.echo(f"Compression:         bzip2")

        # Show parity information if present
        if parity_pages > 0:
            click.echo(f"Parity Pages:        {parity_pages} ({parity_info['total_parity']} total, can recover {parity_pages} missing pages)")
            click.echo(f"Data Pages:          {data_pages}")
            overhead_pct = (parity_pages / data_pages * 100) if data_pages > 0 else 0
            click.echo(f"Parity Overhead:     {overhead_pct:.1f}%")
        else:
            click.echo(f"Parity Pages:        None")

        click.echo(f"QR Codes per Page:   ~{len(chunk_binaries)}")
        click.echo(f"Total QR Codes:      {total_qr_codes}")
        click.echo(f"PDF Pages:           {len(images)}")
        click.echo(f"{'='*60}\n")

    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
