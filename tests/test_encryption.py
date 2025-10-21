"""
Unit tests for encryption functions

Tests for AES-256-GCM encryption with Argon2id key derivation.
"""

import os
import sys
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qr_code_backup as qcb


class TestKeyDerivation:
    """Tests for Argon2id key derivation functions"""

    def test_key_derivation_deterministic(self):
        """Test that same inputs produce same key."""
        password = "test_password_123"
        salt = b"1234567890123456"  # 16 bytes

        key1 = qcb.derive_key(password, salt, 3, 65536, 4)
        key2 = qcb.derive_key(password, salt, 3, 65536, 4)

        assert key1 == key2, "Same inputs should produce same key"
        assert len(key1) == 32, "Key should be 32 bytes (256 bits)"

    def test_key_derivation_different_salts(self):
        """Test that different salts produce different keys."""
        password = "test_password"
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)

        key1 = qcb.derive_key(password, salt1)
        key2 = qcb.derive_key(password, salt2)

        assert key1 != key2, "Different salts should produce different keys"

    def test_verification_hash(self):
        """Test password verification."""
        password = "correct_password"
        wrong_password = "wrong_password"
        salt = os.urandom(16)

        key = qcb.derive_key(password, salt)
        verification_hash = qcb.create_verification_hash(key)

        # Correct password
        assert qcb.verify_password(password, salt, verification_hash, 3, 65536, 4), \
            "Correct password should verify"

        # Wrong password
        assert not qcb.verify_password(wrong_password, salt, verification_hash, 3, 65536, 4), \
            "Wrong password should not verify"

    def test_argon2_parameters(self):
        """Test different Argon2 parameters produce different keys."""
        password = "password"
        salt = os.urandom(16)

        # Different time costs
        key1 = qcb.derive_key(password, salt, time_cost=2)
        key2 = qcb.derive_key(password, salt, time_cost=5)
        assert key1 != key2, "Different time costs should produce different keys"

        # Different memory costs
        key3 = qcb.derive_key(password, salt, memory_cost=32768)
        key4 = qcb.derive_key(password, salt, memory_cost=131072)
        assert key3 != key4, "Different memory costs should produce different keys"


class TestEncryptionDecryption:
    """Tests for AES-256-GCM encryption and decryption"""

    def test_encryption_decryption_round_trip(self):
        """Test encryption and decryption round trip."""
        data = b"This is secret data" * 1000
        password = "secure_password_123"

        # Encrypt
        enc_result = qcb.encrypt_data(data, password)

        # Decrypt with correct password
        decrypted = qcb.decrypt_data(
            enc_result['ciphertext'],
            password,
            enc_result['salt'],
            enc_result['nonce'],
            enc_result['verification_hash'],
            enc_result['time_cost'],
            enc_result['memory_cost'],
            enc_result['parallelism']
        )

        assert decrypted == data, "Decrypted data should match original"

    def test_wrong_password(self):
        """Test decryption fails with wrong password."""
        data = b"Secret data"
        password = "correct"
        wrong = "incorrect"

        enc_result = qcb.encrypt_data(data, password)

        with pytest.raises(ValueError, match="Incorrect password"):
            qcb.decrypt_data(
                enc_result['ciphertext'],
                wrong,  # Wrong password
                enc_result['salt'],
                enc_result['nonce'],
                enc_result['verification_hash'],
                enc_result['time_cost'],
                enc_result['memory_cost'],
                enc_result['parallelism']
            )

    def test_tampered_ciphertext(self):
        """Test decryption fails if ciphertext is modified."""
        data = b"Secret data"
        password = "password123"

        enc_result = qcb.encrypt_data(data, password)

        # Tamper with ciphertext
        tampered = bytearray(enc_result['ciphertext'])
        tampered[10] ^= 0xFF  # Flip some bits

        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            qcb.decrypt_data(
                bytes(tampered),
                password,
                enc_result['salt'],
                enc_result['nonce'],
                enc_result['verification_hash'],
                enc_result['time_cost'],
                enc_result['memory_cost'],
                enc_result['parallelism']
            )

    def test_encryption_metadata(self):
        """Test encryption metadata structure."""
        data = b"Test"
        password = "pass"

        result = qcb.encrypt_data(data, password, time_cost=5, memory_cost=32768, parallelism=2)

        assert len(result['salt']) == 16, "Salt should be 16 bytes"
        assert len(result['nonce']) == 12, "Nonce should be 12 bytes"
        assert len(result['verification_hash']) == 32, "Verification hash should be 32 bytes"
        assert result['time_cost'] == 5, "Time cost should match"
        assert result['memory_cost'] == 32768, "Memory cost should match"
        assert result['parallelism'] == 2, "Parallelism should match"
        assert len(result['ciphertext']) > len(data), "Ciphertext should include auth tag"


class TestMetadataParsing:
    """Tests for binary metadata parsing with encryption support"""

    def test_parse_unencrypted_chunk(self):
        """Test parsing unencrypted chunk (backward compatibility)."""
        import hashlib
        md5 = hashlib.md5(b"data").digest()
        chunk = bytearray()
        chunk.append(0x00)  # Not encrypted
        chunk.extend(md5)
        chunk.extend((1).to_bytes(2, 'big'))  # Page 1
        chunk.append(0x00)  # Parity flag = 0x00 (data page)
        chunk.extend((1000).to_bytes(4, 'big'))  # File size
        chunk.extend(b"compressed_data")

        parsed = qcb.parse_binary_chunk(bytes(chunk))

        assert parsed is not None
        assert parsed['encrypted'] == False
        assert parsed['md5_hash'] == md5
        assert parsed['page_number'] == 1
        assert parsed['is_parity'] == False
        assert parsed['file_size'] == 1000
        assert parsed['data'] == b"compressed_data"

    def test_parse_encrypted_chunk_page1(self):
        """Test parsing encrypted page 1 with full metadata."""
        import hashlib
        md5 = hashlib.md5(b"encrypted_data").digest()
        salt = os.urandom(16)
        verification_hash = os.urandom(32)
        nonce = os.urandom(12)

        chunk = bytearray()
        chunk.append(0x01)  # Encrypted
        chunk.extend(md5)
        chunk.extend((1).to_bytes(2, 'big'))  # Page 1
        chunk.append(0x00)  # Parity flag = 0x00 (data page)
        chunk.extend((5000).to_bytes(4, 'big'))  # File size
        chunk.extend(salt)
        chunk.extend((3).to_bytes(4, 'big'))  # time_cost
        chunk.extend((65536).to_bytes(4, 'big'))  # memory_cost
        chunk.extend((4).to_bytes(4, 'big'))  # parallelism
        chunk.extend(verification_hash)
        chunk.extend(nonce)
        chunk.extend(b"encrypted_chunk_data")

        parsed = qcb.parse_binary_chunk(bytes(chunk))

        assert parsed is not None
        assert parsed['encrypted'] == True
        assert parsed['page_number'] == 1
        assert parsed['is_parity'] == False
        assert parsed['file_size'] == 5000
        assert parsed['salt'] == salt
        assert parsed['time_cost'] == 3
        assert parsed['memory_cost'] == 65536
        assert parsed['parallelism'] == 4
        assert parsed['verification_hash'] == verification_hash
        assert parsed['nonce'] == nonce
        assert parsed['data'] == b"encrypted_chunk_data"

    def test_parse_encrypted_chunk_page2(self):
        """Test parsing encrypted page 2+ (no encryption metadata)."""
        import hashlib
        md5 = hashlib.md5(b"encrypted_data").digest()

        chunk = bytearray()
        chunk.append(0x01)  # Encrypted
        chunk.extend(md5)
        chunk.extend((2).to_bytes(2, 'big'))  # Page 2
        chunk.append(0x00)  # Parity flag = 0x00 (data page)
        chunk.extend(b"encrypted_chunk_data")

        parsed = qcb.parse_binary_chunk(bytes(chunk))

        assert parsed is not None
        assert parsed['encrypted'] == True
        assert parsed['page_number'] == 2
        assert parsed['is_parity'] == False
        assert 'file_size' in parsed
        assert parsed['file_size'] is None  # Not page 1
        assert 'salt' not in parsed
        assert parsed['data'] == b"encrypted_chunk_data"


class TestIntegration:
    """Integration tests for full encrypted encode-decode cycle"""

    def test_encrypted_create_chunks(self):
        """Test creating encrypted chunks."""
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Test data" * 100)
            test_file = f.name

        try:
            password = "test_password_123"
            chunks = qcb.create_chunks(
                test_file,
                chunk_size=300,
                compression='bzip2',
                encrypt=True,
                password=password
            )

            # Parse page 1
            parsed = qcb.parse_binary_chunk(chunks[0])
            assert parsed['encrypted'] == True
            assert 'salt' in parsed
            assert 'verification_hash' in parsed
            assert 'nonce' in parsed

        finally:
            os.unlink(test_file)

    def test_full_encrypted_cycle(self):
        """Test complete encrypted encode-decode cycle."""
        import tempfile
        import filecmp

        test_data = b"Sensitive information" * 100
        password = "encryption_password_123"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            output_file = os.path.join(tmpdir, 'output.bin')

            # Write test data
            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with encryption
            chunks = qcb.create_chunks(input_file, chunk_size=300, encrypt=True, password=password)

            # Decode with password
            file_data, report = qcb.reassemble_chunks(chunks, password=password)

            # Write output
            with open(output_file, 'wb') as f:
                f.write(file_data)

            # Verify
            assert filecmp.cmp(input_file, output_file)
            assert report['decryption'] == 'success'

    def test_encrypted_without_password_fails(self):
        """Test that encrypted chunks fail without password."""
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Secret data")
            test_file = f.name

        try:
            chunks = qcb.create_chunks(
                test_file,
                chunk_size=200,
                encrypt=True,
                password="secret"
            )

            with pytest.raises(ValueError, match="encrypted but no password"):
                qcb.reassemble_chunks(chunks, password=None)
        finally:
            os.unlink(test_file)

    def test_encrypted_wrong_password_fails(self):
        """Test that wrong password is detected."""
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Secret")
            test_file = f.name

        try:
            chunks = qcb.create_chunks(
                test_file,
                chunk_size=200,
                encrypt=True,
                password="correct"
            )

            with pytest.raises(ValueError, match="Incorrect password"):
                qcb.reassemble_chunks(chunks, password="wrong")
        finally:
            os.unlink(test_file)

    def test_backward_compatibility_unencrypted(self):
        """Test that unencrypted chunks still work (backward compatibility)."""
        import tempfile
        import filecmp

        test_data = b"Unencrypted data"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            output_file = os.path.join(tmpdir, 'output.bin')

            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Create chunks without encryption (old style)
            chunks = qcb.create_chunks(input_file, chunk_size=200, encrypt=False)

            # Decode without password
            file_data, report = qcb.reassemble_chunks(chunks, password=None)

            with open(output_file, 'wb') as f:
                f.write(file_data)

            assert filecmp.cmp(input_file, output_file)
            assert 'decryption' not in report  # No decryption happened


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
