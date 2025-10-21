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


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
