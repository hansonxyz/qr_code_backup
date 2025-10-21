"""
Unit tests for decoding functionality
"""

import os
import sys
import json
import base64
import tempfile

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qr_code_backup as qcb


class TestQRDataParsing:
    """Test QR code data parsing"""

    def test_parse_valid_qr_data(self):
        """Test parsing valid JSON from QR code"""
        test_metadata = {
            'format_version': '1.0',
            'file_name': 'test.txt',
            'page_number': 1,
            'total_pages': 1,
            'data': base64.b64encode(b'test').decode('ascii')
        }

        json_string = json.dumps(test_metadata)
        parsed = qcb.parse_qr_data(json_string)

        assert parsed is not None
        assert parsed['file_name'] == 'test.txt'
        assert parsed['page_number'] == 1

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON returns None"""
        invalid_data = "This is not JSON"
        parsed = qcb.parse_qr_data(invalid_data)

        assert parsed is None

    def test_parse_empty_string(self):
        """Test parsing empty string"""
        parsed = qcb.parse_qr_data("")

        assert parsed is None


class TestChunkReassembly:
    """Test chunk reassembly functionality"""

    def test_reassemble_single_chunk(self):
        """Test reassembling a single chunk"""
        # Create test data
        original_data = b"Hello, World!"
        checksum = qcb.calculate_checksum(original_data)

        chunk = {
            'format_version': '1.0',
            'file_name': 'test.txt',
            'file_size': len(original_data),
            'total_pages': 1,
            'page_number': 1,
            'chunk_size': len(original_data),
            'checksum_type': 'sha256',
            'file_checksum': checksum,
            'chunk_checksum': qcb.calculate_checksum(original_data),
            'compression': 'none',
            'data': base64.b64encode(original_data).decode('ascii')
        }

        file_data, report = qcb.reassemble_chunks([chunk], verify=True)

        assert file_data == original_data
        assert report['total_pages'] == 1
        assert report['found_pages'] == 1
        assert len(report['missing_pages']) == 0
        assert len(report['checksum_failures']) == 0

    def test_reassemble_multiple_chunks(self):
        """Test reassembling multiple chunks in correct order"""
        # Create multi-chunk data
        original_data = b"AAAABBBBCCCCDDDD"
        chunk_size = 4

        chunks = []
        for i in range(4):
            chunk_data = original_data[i*chunk_size:(i+1)*chunk_size]

            chunk = {
                'format_version': '1.0',
                'file_name': 'test.bin',
                'file_size': len(original_data),
                'total_pages': 4,
                'page_number': i + 1,
                'chunk_size': len(chunk_data),
                'checksum_type': 'sha256',
                'file_checksum': qcb.calculate_checksum(original_data),
                'chunk_checksum': qcb.calculate_checksum(chunk_data),
                'compression': 'none',
                'data': base64.b64encode(chunk_data).decode('ascii')
            }
            chunks.append(chunk)

        # Test with chunks in order
        file_data, report = qcb.reassemble_chunks(chunks, verify=True)

        assert file_data == original_data
        assert report['found_pages'] == 4
        assert len(report['missing_pages']) == 0

    def test_reassemble_out_of_order_chunks(self):
        """Test reassembling chunks provided in wrong order"""
        original_data = b"AAAABBBBCCCCDDDD"
        chunk_size = 4

        chunks = []
        for i in range(4):
            chunk_data = original_data[i*chunk_size:(i+1)*chunk_size]

            chunk = {
                'format_version': '1.0',
                'file_name': 'test.bin',
                'file_size': len(original_data),
                'total_pages': 4,
                'page_number': i + 1,
                'chunk_size': len(chunk_data),
                'checksum_type': 'sha256',
                'file_checksum': qcb.calculate_checksum(original_data),
                'chunk_checksum': qcb.calculate_checksum(chunk_data),
                'compression': 'none',
                'data': base64.b64encode(chunk_data).decode('ascii')
            }
            chunks.append(chunk)

        # Shuffle chunks
        shuffled = [chunks[2], chunks[0], chunks[3], chunks[1]]

        file_data, report = qcb.reassemble_chunks(shuffled, verify=True)

        # Should still reassemble correctly
        assert file_data == original_data

    def test_reassemble_with_compression(self):
        """Test reassembling compressed data"""
        original_data = b"Test data that will be compressed"
        compressed_data = qcb.compress_data(original_data, 'gzip')

        chunk = {
            'format_version': '1.0',
            'file_name': 'test.txt',
            'file_size': len(original_data),
            'total_pages': 1,
            'page_number': 1,
            'chunk_size': len(compressed_data),
            'checksum_type': 'sha256',
            'file_checksum': qcb.calculate_checksum(original_data),
            'chunk_checksum': qcb.calculate_checksum(compressed_data),
            'compression': 'gzip',
            'data': base64.b64encode(compressed_data).decode('ascii')
        }

        file_data, report = qcb.reassemble_chunks([chunk], verify=True)

        assert file_data == original_data
        assert report['compression'] == 'gzip'

    def test_reassemble_missing_pages_fails(self):
        """Test that missing pages are detected"""
        original_data = b"AAAABBBBCCCCDDDD"

        # Create only 2 chunks out of 4
        chunks = []
        for i in [0, 2]:  # Missing pages 2 and 4
            chunk_data = original_data[i*4:(i+1)*4]

            chunk = {
                'format_version': '1.0',
                'file_name': 'test.bin',
                'file_size': len(original_data),
                'total_pages': 4,
                'page_number': i + 1,
                'chunk_size': len(chunk_data),
                'checksum_type': 'sha256',
                'file_checksum': qcb.calculate_checksum(original_data),
                'chunk_checksum': qcb.calculate_checksum(chunk_data),
                'compression': 'none',
                'data': base64.b64encode(chunk_data).decode('ascii')
            }
            chunks.append(chunk)

        # Should raise error without recovery mode
        try:
            qcb.reassemble_chunks(chunks, verify=True, recovery_mode=False)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Missing" in str(e)

    def test_reassemble_recovery_mode(self):
        """Test recovery mode with missing pages"""
        original_data = b"AAAABBBBCCCCDDDD"

        # Create only 2 chunks out of 4
        chunks = []
        for i in [0, 2]:  # Missing pages 2 and 4
            chunk_data = original_data[i*4:(i+1)*4]

            chunk = {
                'format_version': '1.0',
                'file_name': 'test.bin',
                'file_size': len(original_data),
                'total_pages': 4,
                'page_number': i + 1,
                'chunk_size': len(chunk_data),
                'checksum_type': 'sha256',
                'file_checksum': qcb.calculate_checksum(original_data),
                'chunk_checksum': qcb.calculate_checksum(chunk_data),
                'compression': 'none',
                'data': base64.b64encode(chunk_data).decode('ascii')
            }
            chunks.append(chunk)

        # With recovery mode, should not raise error
        file_data, report = qcb.reassemble_chunks(chunks, verify=True, recovery_mode=True)

        # Should have partial data
        assert len(file_data) > 0
        assert report['missing_pages'] == [2, 4]

    def test_reassemble_checksum_failure(self):
        """Test detection of corrupted chunk"""
        original_data = b"Test data"
        corrupt_data = b"Bad data!"  # Wrong data

        chunk = {
            'format_version': '1.0',
            'file_name': 'test.txt',
            'file_size': len(original_data),
            'total_pages': 1,
            'page_number': 1,
            'chunk_size': len(corrupt_data),
            'checksum_type': 'sha256',
            'file_checksum': qcb.calculate_checksum(original_data),
            'chunk_checksum': qcb.calculate_checksum(original_data),  # Wrong checksum
            'compression': 'none',
            'data': base64.b64encode(corrupt_data).decode('ascii')
        }

        # Should detect checksum mismatch
        try:
            qcb.reassemble_chunks([chunk], verify=True, recovery_mode=False)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "checksum" in str(e).lower()

    def test_reassemble_without_verification(self):
        """Test reassembly without checksum verification"""
        original_data = b"Test"
        corrupt_data = b"Bad!"

        chunk = {
            'format_version': '1.0',
            'file_name': 'test.txt',
            'file_size': len(original_data),
            'total_pages': 1,
            'page_number': 1,
            'chunk_size': len(corrupt_data),
            'checksum_type': 'sha256',
            'file_checksum': qcb.calculate_checksum(original_data),
            'chunk_checksum': qcb.calculate_checksum(original_data),
            'compression': 'none',
            'data': base64.b64encode(corrupt_data).decode('ascii')
        }

        # Should not raise error if verify=False
        file_data, report = qcb.reassemble_chunks([chunk], verify=False, recovery_mode=False)

        assert file_data == corrupt_data  # Gets the corrupt data


class TestMetadataExtraction:
    """Test metadata extraction from chunks"""

    def test_metadata_consistency(self):
        """Test that metadata is consistent across chunks"""
        # Create chunks with same metadata
        chunks = []
        for i in range(3):
            chunk = {
                'format_version': '1.0',
                'file_name': 'consistent.txt',
                'file_size': 100,
                'total_pages': 3,
                'page_number': i + 1,
                'chunk_size': 33,
                'checksum_type': 'sha256',
                'file_checksum': 'abc123',
                'chunk_checksum': f'chunk{i}',
                'compression': 'gzip',
                'data': base64.b64encode(b'X' * 33).decode('ascii')
            }
            chunks.append(chunk)

        # All chunks should have same file metadata
        assert all(c['file_name'] == 'consistent.txt' for c in chunks)
        assert all(c['file_size'] == 100 for c in chunks)
        assert all(c['total_pages'] == 3 for c in chunks)
        assert all(c['file_checksum'] == 'abc123' for c in chunks)


class TestErrorHandling:
    """Test error handling in decode functions"""

    def test_empty_chunks_list(self):
        """Test error handling for empty chunks list"""
        try:
            qcb.reassemble_chunks([], verify=True)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "No chunks" in str(e)

    def test_invalid_compression_type(self):
        """Test error handling for invalid compression"""
        try:
            qcb.decompress_data(b"data", "invalid")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "compression" in str(e).lower()


class TestOrderIndependentDecoding:
    """Test order-independent decoding with binary format"""

    def test_pages_in_correct_order(self):
        """Test reassembly when pages are already in correct order"""
        import hashlib
        import bz2

        # Create binary chunks for pages 1, 2, 3
        original_data = b"test data for compression"
        compressed_data = bz2.compress(original_data)
        md5_hash = hashlib.md5(compressed_data).digest()
        file_size = len(original_data)

        chunks = []
        chunk_size = len(compressed_data) // 3
        for page_num in [1, 2, 3]:
            chunk = bytearray()
            chunk.extend(md5_hash)  # MD5 hash (16 bytes)
            chunk.extend(page_num.to_bytes(2, 'big'))  # Page number (2 bytes)

            if page_num == 1:
                chunk.extend(file_size.to_bytes(4, 'big'))  # File size (4 bytes, only page 1)
                data_start = 0
            else:
                data_start = chunk_size * (page_num - 1)

            data_end = chunk_size * page_num if page_num < 3 else len(compressed_data)
            chunk.extend(compressed_data[data_start:data_end])
            chunks.append(bytes(chunk))

        # Decode in order
        file_data, report = qcb.reassemble_chunks(chunks, verify=True, recovery_mode=False)

        # Should succeed
        assert file_data == original_data
        assert report['found_pages'] == 3

    def test_pages_reversed(self):
        """Test reassembly when pages are in reverse order (3, 2, 1)"""
        import hashlib
        import bz2

        original_data = b"reverse order test data"
        compressed_data = bz2.compress(original_data)
        md5_hash = hashlib.md5(compressed_data).digest()
        file_size = len(original_data)

        chunks = []
        chunk_size = len(compressed_data) // 3
        for page_num in [1, 2, 3]:
            chunk = bytearray()
            chunk.extend(md5_hash)
            chunk.extend(page_num.to_bytes(2, 'big'))

            if page_num == 1:
                chunk.extend(file_size.to_bytes(4, 'big'))
                data_start = 0
            else:
                data_start = chunk_size * (page_num - 1)

            data_end = chunk_size * page_num if page_num < 3 else len(compressed_data)
            chunk.extend(compressed_data[data_start:data_end])
            chunks.append(bytes(chunk))

        # Reverse order
        reversed_chunks = list(reversed(chunks))

        # Should still reassemble correctly
        file_data, report = qcb.reassemble_chunks(reversed_chunks, verify=True)

        assert file_data == original_data
        assert report['found_pages'] == 3

    def test_pages_random_order(self):
        """Test reassembly with randomly shuffled pages"""
        import hashlib
        import bz2

        original_data = b"random order test with enough data for shuffling"
        compressed_data = bz2.compress(original_data)
        md5_hash = hashlib.md5(compressed_data).digest()
        file_size = len(original_data)

        chunks = []
        chunk_size = len(compressed_data) // 5
        for page_num in range(1, 6):  # 5 pages
            chunk = bytearray()
            chunk.extend(md5_hash)
            chunk.extend(page_num.to_bytes(2, 'big'))

            if page_num == 1:
                chunk.extend(file_size.to_bytes(4, 'big'))
                data_start = 0
            else:
                data_start = chunk_size * (page_num - 1)

            data_end = chunk_size * page_num if page_num < 5 else len(compressed_data)
            chunk.extend(compressed_data[data_start:data_end])
            chunks.append(bytes(chunk))

        # Shuffle: 3, 1, 5, 2, 4
        shuffled = [chunks[2], chunks[0], chunks[4], chunks[1], chunks[3]]

        # Should still work
        file_data, report = qcb.reassemble_chunks(shuffled, verify=True)

        assert file_data == original_data
        assert report['found_pages'] == 5

    def test_pages_interleaved(self):
        """Test reassembly with interleaved order (1, 5, 2, 4, 3)"""
        import hashlib
        import bz2

        original_data = b"interleaved test data for proper validation"
        compressed_data = bz2.compress(original_data)
        md5_hash = hashlib.md5(compressed_data).digest()
        file_size = len(original_data)

        chunks = []
        chunk_size = len(compressed_data) // 5
        for page_num in range(1, 6):
            chunk = bytearray()
            chunk.extend(md5_hash)
            chunk.extend(page_num.to_bytes(2, 'big'))

            if page_num == 1:
                chunk.extend(file_size.to_bytes(4, 'big'))
                data_start = 0
            else:
                data_start = chunk_size * (page_num - 1)

            data_end = chunk_size * page_num if page_num < 5 else len(compressed_data)
            chunk.extend(compressed_data[data_start:data_end])
            chunks.append(bytes(chunk))

        # Specific interleaved order
        weird_order = [chunks[0], chunks[4], chunks[1], chunks[3], chunks[2]]

        file_data, report = qcb.reassemble_chunks(weird_order, verify=True)

        assert file_data == original_data
        assert report['found_pages'] == 5


class TestMixedDocumentDetection:
    """Test detection of mixed documents with binary format"""

    def test_same_document_all_chunks(self):
        """Test that chunks from same document are accepted"""
        import hashlib
        import bz2

        original_data = b"same document test data"
        compressed_data = bz2.compress(original_data)
        md5_hash = hashlib.md5(compressed_data).digest()
        file_size = len(original_data)

        chunks = []
        chunk_size = len(compressed_data) // 3
        for page_num in range(1, 4):
            chunk = bytearray()
            chunk.extend(md5_hash)  # Same MD5 for all
            chunk.extend(page_num.to_bytes(2, 'big'))

            if page_num == 1:
                chunk.extend(file_size.to_bytes(4, 'big'))
                data_start = 0
            else:
                data_start = chunk_size * (page_num - 1)

            data_end = chunk_size * page_num if page_num < 3 else len(compressed_data)
            chunk.extend(compressed_data[data_start:data_end])
            chunks.append(bytes(chunk))

        # Should succeed
        file_data, report = qcb.reassemble_chunks(chunks, verify=True)

        assert file_data == original_data
        assert report['found_pages'] == 3

    def test_mixed_documents_detected(self):
        """Test that mixing chunks from different documents fails"""
        import hashlib

        # Two different documents with different MD5s
        doc_a_data = b"document_a_compressed_data"
        doc_b_data = b"document_b_compressed_data"
        md5_a = hashlib.md5(doc_a_data).digest()
        md5_b = hashlib.md5(doc_b_data).digest()

        # Create chunks from doc A (pages 1-2)
        chunks = []
        for page_num in [1, 2]:
            chunk = bytearray()
            chunk.extend(md5_a)
            chunk.extend(page_num.to_bytes(2, 'big'))

            if page_num == 1:
                chunk.extend((100).to_bytes(4, 'big'))

            chunk.extend(f"doc_a_{page_num}".encode())
            chunks.append(bytes(chunk))

        # Add chunk from doc B (page 3)
        chunk_b = bytearray()
        chunk_b.extend(md5_b)  # Different MD5!
        chunk_b.extend((3).to_bytes(2, 'big'))
        chunk_b.extend(b"doc_b_3")
        chunks.append(bytes(chunk_b))

        # Should fail with mixed documents error
        try:
            qcb.reassemble_chunks(chunks, verify=True, recovery_mode=False)
            assert False, "Should have raised ValueError for mixed documents"
        except ValueError as e:
            assert "Mixed documents detected" in str(e)

    def test_duplicate_pages_detected(self):
        """Test that duplicate page numbers are detected"""
        import hashlib

        compressed_data = b"dup_test_data_compressed"
        md5_hash = hashlib.md5(compressed_data).digest()
        file_size = 90

        chunks = []
        # Page 1
        chunk1 = bytearray()
        chunk1.extend(md5_hash)
        chunk1.extend((1).to_bytes(2, 'big'))
        chunk1.extend(file_size.to_bytes(4, 'big'))
        chunk1.extend(b"page1")
        chunks.append(bytes(chunk1))

        # Page 2 (first)
        chunk2a = bytearray()
        chunk2a.extend(md5_hash)
        chunk2a.extend((2).to_bytes(2, 'big'))
        chunk2a.extend(b"page2a")
        chunks.append(bytes(chunk2a))

        # Page 2 (duplicate)
        chunk2b = bytearray()
        chunk2b.extend(md5_hash)
        chunk2b.extend((2).to_bytes(2, 'big'))  # Duplicate!
        chunk2b.extend(b"page2b")
        chunks.append(bytes(chunk2b))

        # Should fail with duplicate error
        try:
            qcb.reassemble_chunks(chunks, verify=True, recovery_mode=False)
            assert False, "Should have raised ValueError for duplicates"
        except ValueError as e:
            assert "Duplicate" in str(e)


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
