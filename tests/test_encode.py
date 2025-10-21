"""
Unit tests for encoding functionality
"""

import os
import sys
import tempfile
import json
import base64
from pathlib import Path

# Add parent directory to path to import qr_code_backup
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qr_code_backup as qcb
from PIL import Image


class TestChecksumCalculation:
    """Test checksum functions"""

    def test_sha256_checksum(self):
        """Test SHA-256 checksum calculation"""
        data = b"Hello, World!"
        checksum = qcb.calculate_checksum(data, 'sha256')

        # Known SHA-256 hash of "Hello, World!"
        expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        assert checksum == expected

    def test_md5_checksum(self):
        """Test MD5 checksum calculation"""
        data = b"Hello, World!"
        checksum = qcb.calculate_checksum(data, 'md5')

        # Known MD5 hash of "Hello, World!"
        expected = "65a8e27d8879283831b664bd8b7f0ad4"
        assert checksum == expected

    def test_checksum_consistency(self):
        """Test that same data produces same checksum"""
        data = b"Test data for consistency"
        checksum1 = qcb.calculate_checksum(data)
        checksum2 = qcb.calculate_checksum(data)

        assert checksum1 == checksum2


class TestCompression:
    """Test compression and decompression"""

    def test_gzip_compression_decompression(self):
        """Test gzip compression round trip"""
        original_data = b"This is test data that should compress well. " * 100

        compressed = qcb.compress_data(original_data, 'gzip')
        decompressed = qcb.decompress_data(compressed, 'gzip')

        assert decompressed == original_data
        assert len(compressed) < len(original_data)  # Should be smaller

    def test_bzip2_compression_decompression(self):
        """Test bzip2 compression round trip"""
        original_data = b"Test data for bzip2 compression. " * 50

        compressed = qcb.compress_data(original_data, 'bzip2')
        decompressed = qcb.decompress_data(compressed, 'bzip2')

        assert decompressed == original_data
        assert len(compressed) < len(original_data)

    def test_no_compression(self):
        """Test 'none' compression returns original data"""
        original_data = b"Uncompressed data"

        compressed = qcb.compress_data(original_data, 'none')
        decompressed = qcb.decompress_data(compressed, 'none')

        assert compressed == original_data
        assert decompressed == original_data


class TestQRCapacity:
    """Test QR code capacity calculations"""

    def test_qr_capacity_version_10(self):
        """Test capacity calculation for version 10"""
        capacity = qcb.get_qr_capacity(10, 'M')
        assert capacity > 0
        assert capacity == 271  # Known value for version 10, error correction M

    def test_qr_capacity_different_error_levels(self):
        """Test that higher error correction reduces capacity"""
        version = 15

        capacity_l = qcb.get_qr_capacity(version, 'L')
        capacity_m = qcb.get_qr_capacity(version, 'M')
        capacity_q = qcb.get_qr_capacity(version, 'Q')
        capacity_h = qcb.get_qr_capacity(version, 'H')

        # L should have highest capacity, H lowest
        assert capacity_l > capacity_m > capacity_q > capacity_h

    def test_chunk_size_calculation(self):
        """Test chunk size accounts for overhead"""
        chunk_size = qcb.calculate_chunk_size(15, 'M')

        assert chunk_size > 0
        assert chunk_size < qcb.get_qr_capacity(15, 'M')  # Less than raw capacity


class TestFileChunking:
    """Test file chunking functionality"""

    def test_chunking_small_file(self):
        """Test chunking a small file that fits in one chunk"""
        # Create temporary test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            test_file = f.name
            f.write("Small test file content")

        try:
            chunks = qcb.create_chunks(test_file, chunk_size=1000, compression='none')

            # Should be only 1 chunk
            assert len(chunks) == 1

            # Check metadata structure
            chunk = chunks[0]
            assert chunk['format_version'] == qcb.FORMAT_VERSION
            assert chunk['file_name'] == os.path.basename(test_file)
            assert chunk['total_pages'] == 1
            assert chunk['page_number'] == 1
            assert chunk['compression'] == 'none'
            assert 'file_checksum' in chunk
            assert 'chunk_checksum' in chunk
            assert 'data' in chunk

            # Verify data can be decoded
            decoded_data = base64.b64decode(chunk['data'])
            assert decoded_data == b"Small test file content"

        finally:
            os.unlink(test_file)

    def test_chunking_multiple_chunks(self):
        """Test chunking a file into multiple chunks"""
        # Create file that will require multiple chunks
        test_data = b"X" * 5000  # 5000 bytes

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_file = f.name
            f.write(test_data)

        try:
            chunk_size = 1000
            chunks = qcb.create_chunks(test_file, chunk_size=chunk_size, compression='none')

            # Should be 5 chunks
            assert len(chunks) == 5

            # Verify page numbers are sequential
            page_numbers = [c['page_number'] for c in chunks]
            assert page_numbers == [1, 2, 3, 4, 5]

            # Verify all have same total_pages
            assert all(c['total_pages'] == 5 for c in chunks)

            # Verify all have same file_checksum
            file_checksum = chunks[0]['file_checksum']
            assert all(c['file_checksum'] == file_checksum for c in chunks)

            # Verify data can be reassembled
            reassembled = b''
            for chunk in chunks:
                reassembled += base64.b64decode(chunk['data'])

            assert reassembled == test_data

        finally:
            os.unlink(test_file)

    def test_chunking_with_compression(self):
        """Test chunking with compression enabled"""
        # Create highly compressible data
        test_data = b"AAAA" * 1000  # Very repetitive

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            test_file = f.name
            f.write(test_data)

        try:
            chunks_compressed = qcb.create_chunks(test_file, chunk_size=1000, compression='gzip')
            chunks_uncompressed = qcb.create_chunks(test_file, chunk_size=1000, compression='none')

            # Compressed version should have fewer chunks
            assert len(chunks_compressed) < len(chunks_uncompressed)

            # Verify compression flag is set
            assert chunks_compressed[0]['compression'] == 'gzip'
            assert chunks_uncompressed[0]['compression'] == 'none'

        finally:
            os.unlink(test_file)


class TestQRCodeGeneration:
    """Test QR code generation"""

    def test_create_qr_code(self):
        """Test basic QR code creation"""
        test_data = {
            'format_version': '1.0',
            'file_name': 'test.txt',
            'page_number': 1,
            'total_pages': 1,
            'data': base64.b64encode(b'test').decode('ascii')
        }

        img = qcb.create_qr_code(test_data, qr_version=5, error_correction='M')

        # Should return PIL-compatible Image (qrcode returns PilImage which has Image.Image interface)
        assert hasattr(img, 'size')
        assert hasattr(img, 'save')

        # Should be square
        width, height = img.size
        assert width == height

        # Should be reasonably sized
        assert width > 0

    def test_qr_code_different_error_corrections(self):
        """Test QR code generation with different error correction levels"""
        test_data = {'test': 'data'}

        for level in ['L', 'M', 'Q', 'H']:
            img = qcb.create_qr_code(test_data, qr_version=10, error_correction=level)
            assert hasattr(img, 'size')
            assert hasattr(img, 'save')

    def test_qr_code_auto_version(self):
        """Test QR code with auto version selection"""
        test_data = {'small': 'data'}

        img = qcb.create_qr_code(test_data, qr_version=None, error_correction='M')
        assert hasattr(img, 'size')
        assert hasattr(img, 'save')


class TestPDFGeneration:
    """Test PDF generation functionality"""

    def test_generate_single_page_pdf(self):
        """Test generating a single-page PDF"""
        # Create a simple QR code
        test_data = {'test': 'data'}
        qr_img = qcb.create_qr_code(test_data, qr_version=5, error_correction='M')

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as f:
            pdf_path = f.name

        try:
            qcb.generate_pdf(
                qr_images=[qr_img],
                output_path=pdf_path,
                title="Test PDF",
                page_size='A4',
                qrs_per_page=(3, 3),
                qr_size_mm=60,
                no_header=False,
                total_pages=1
            )

            # Verify PDF was created
            assert os.path.exists(pdf_path)
            assert os.path.getsize(pdf_path) > 0

        finally:
            if os.path.exists(pdf_path):
                os.unlink(pdf_path)

    def test_generate_multi_page_pdf(self):
        """Test generating a multi-page PDF"""
        # Create multiple QR codes
        qr_images = []
        for i in range(20):  # Enough for 3 pages at 3x3 grid
            test_data = {'page': i}
            qr_img = qcb.create_qr_code(test_data, qr_version=5, error_correction='M')
            qr_images.append(qr_img)

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as f:
            pdf_path = f.name

        try:
            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=pdf_path,
                title="Multi-page Test",
                page_size='A4',
                qrs_per_page=(3, 3),
                qr_size_mm=60,
                no_header=False,
                total_pages=20
            )

            # Verify PDF was created and has reasonable size
            assert os.path.exists(pdf_path)
            assert os.path.getsize(pdf_path) > 1000  # Should be substantial

        finally:
            if os.path.exists(pdf_path):
                os.unlink(pdf_path)

    def test_generate_pdf_no_header(self):
        """Test PDF generation without headers"""
        test_data = {'test': 'data'}
        qr_img = qcb.create_qr_code(test_data, qr_version=5, error_correction='M')

        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as f:
            pdf_path = f.name

        try:
            qcb.generate_pdf(
                qr_images=[qr_img],
                output_path=pdf_path,
                title="Test",
                page_size='A4',
                qrs_per_page=(3, 3),
                qr_size_mm=60,
                no_header=True,
                total_pages=1
            )

            assert os.path.exists(pdf_path)

        finally:
            if os.path.exists(pdf_path):
                os.unlink(pdf_path)


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
