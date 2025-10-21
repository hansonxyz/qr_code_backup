"""
Integration tests for full encode-decode cycle
"""

import os
import sys
import tempfile
import filecmp
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qr_code_backup as qcb


class TestFullCycle:
    """Test complete encode-decode workflow"""

    def test_encode_decode_small_text_file(self):
        """Test full cycle with small text file"""
        # Create test file
        test_content = "This is a small test file for QR code backup.\nIt has multiple lines.\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'test.txt')
            pdf_file = os.path.join(tmpdir, 'backup.pdf')
            output_file = os.path.join(tmpdir, 'recovered.txt')

            # Write test file
            with open(input_file, 'w') as f:
                f.write(test_content)

            # Encode
            chunks = qcb.create_chunks(input_file, chunk_size=1000, compression='gzip')
            qr_images = []
            for chunk in chunks:
                img = qcb.create_qr_code(chunk, qr_version=15, error_correction='M')
                qr_images.append(img)

            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=pdf_file,
                title='Test',
                page_size='A4',
                qrs_per_page=(3, 3),
                qr_size_mm=60,
                no_header=False,
                total_pages=len(chunks)
            )

            # Verify PDF exists
            assert os.path.exists(pdf_file)

            # Decode
            images = qcb.pdf_to_images(pdf_file)
            all_chunks = []

            for image in images:
                qr_strings = qcb.decode_qr_codes_from_image(image)
                for qr_str in qr_strings:
                    chunk = qcb.parse_qr_data(qr_str)
                    if chunk:
                        all_chunks.append(chunk)

            # Reassemble
            file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

            # Write output
            with open(output_file, 'wb') as f:
                f.write(file_data)

            # Verify files match
            assert filecmp.cmp(input_file, output_file)

            # Verify report
            assert report['found_pages'] == report['total_pages']
            assert len(report['missing_pages']) == 0
            assert len(report['checksum_failures']) == 0

    def test_encode_decode_binary_file(self):
        """Test full cycle with binary file"""
        # Create binary test file
        test_data = bytes(range(256)) * 10  # 2560 bytes

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'test.bin')
            pdf_file = os.path.join(tmpdir, 'backup.pdf')
            output_file = os.path.join(tmpdir, 'recovered.bin')

            # Write test file
            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode
            chunks = qcb.create_chunks(input_file, chunk_size=500, compression='none')
            qr_images = []
            for chunk in chunks:
                img = qcb.create_qr_code(chunk, qr_version=15, error_correction='M')
                qr_images.append(img)

            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=pdf_file,
                title='Binary Test',
                page_size='A4',
                qrs_per_page=(3, 3),
                qr_size_mm=60,
                no_header=False,
                total_pages=len(chunks)
            )

            # Decode
            images = qcb.pdf_to_images(pdf_file)
            all_chunks = []

            for image in images:
                qr_strings = qcb.decode_qr_codes_from_image(image)
                for qr_str in qr_strings:
                    chunk = qcb.parse_qr_data(qr_str)
                    if chunk:
                        all_chunks.append(chunk)

            # Reassemble
            file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

            # Write output
            with open(output_file, 'wb') as f:
                f.write(file_data)

            # Verify files match
            assert filecmp.cmp(input_file, output_file)

    def test_encode_decode_with_compression(self):
        """Test full cycle with different compression methods"""
        # Create highly compressible test data
        test_data = b"AAAA" * 500  # 2000 bytes, very repetitive

        for compression in ['none', 'gzip', 'bzip2']:
            with tempfile.TemporaryDirectory() as tmpdir:
                input_file = os.path.join(tmpdir, f'test_{compression}.bin')
                pdf_file = os.path.join(tmpdir, f'backup_{compression}.pdf')
                output_file = os.path.join(tmpdir, f'recovered_{compression}.bin')

                # Write test file
                with open(input_file, 'wb') as f:
                    f.write(test_data)

                # Encode
                chunks = qcb.create_chunks(input_file, chunk_size=500, compression=compression)
                qr_images = []
                for chunk in chunks:
                    img = qcb.create_qr_code(chunk, qr_version=15, error_correction='M')
                    qr_images.append(img)

                qcb.generate_pdf(
                    qr_images=qr_images,
                    output_path=pdf_file,
                    title=f'Test {compression}',
                    page_size='A4',
                    qrs_per_page=(3, 3),
                    qr_size_mm=60,
                    no_header=False,
                    total_pages=len(chunks)
                )

                # Decode
                images = qcb.pdf_to_images(pdf_file)
                all_chunks = []

                for image in images:
                    qr_strings = qcb.decode_qr_codes_from_image(image)
                    for qr_str in qr_strings:
                        chunk = qcb.parse_qr_data(qr_str)
                        if chunk:
                            all_chunks.append(chunk)

                # Reassemble
                file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

                # Write output
                with open(output_file, 'wb') as f:
                    f.write(file_data)

                # Verify files match
                assert filecmp.cmp(input_file, output_file)
                assert report['compression'] == compression

    def test_encode_decode_different_error_corrections(self):
        """Test full cycle with different error correction levels"""
        test_data = b"Test data for error correction levels"

        for ec_level in ['L', 'M', 'Q', 'H']:
            with tempfile.TemporaryDirectory() as tmpdir:
                input_file = os.path.join(tmpdir, f'test_{ec_level}.txt')
                pdf_file = os.path.join(tmpdir, f'backup_{ec_level}.pdf')
                output_file = os.path.join(tmpdir, f'recovered_{ec_level}.txt')

                # Write test file
                with open(input_file, 'wb') as f:
                    f.write(test_data)

                # Encode
                chunks = qcb.create_chunks(input_file, chunk_size=500, compression='none')
                qr_images = []
                for chunk in chunks:
                    img = qcb.create_qr_code(chunk, qr_version=10, error_correction=ec_level)
                    qr_images.append(img)

                qcb.generate_pdf(
                    qr_images=qr_images,
                    output_path=pdf_file,
                    title=f'Test EC {ec_level}',
                    page_size='A4',
                    qrs_per_page=(3, 3),
                    qr_size_mm=60,
                    no_header=False,
                    total_pages=len(chunks)
                )

                # Decode
                images = qcb.pdf_to_images(pdf_file)
                all_chunks = []

                for image in images:
                    qr_strings = qcb.decode_qr_codes_from_image(image)
                    for qr_str in qr_strings:
                        chunk = qcb.parse_qr_data(qr_str)
                        if chunk:
                            all_chunks.append(chunk)

                # Reassemble
                file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

                # Write output
                with open(output_file, 'wb') as f:
                    f.write(file_data)

                # Verify files match
                assert filecmp.cmp(input_file, output_file)

    def test_encode_decode_multi_page(self):
        """Test full cycle with file requiring multiple pages"""
        # Create larger file that will require multiple QR codes
        test_data = b"X" * 10000  # 10KB

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'large.bin')
            pdf_file = os.path.join(tmpdir, 'backup_large.pdf')
            output_file = os.path.join(tmpdir, 'recovered_large.bin')

            # Write test file
            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with small chunk size to force multiple pages
            chunks = qcb.create_chunks(input_file, chunk_size=500, compression='none')
            assert len(chunks) > 5  # Should require multiple chunks

            qr_images = []
            for chunk in chunks:
                img = qcb.create_qr_code(chunk, qr_version=15, error_correction='M')
                qr_images.append(img)

            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=pdf_file,
                title='Large Test',
                page_size='A4',
                qrs_per_page=(3, 3),
                qr_size_mm=60,
                no_header=False,
                total_pages=len(chunks)
            )

            # Decode
            images = qcb.pdf_to_images(pdf_file)
            assert len(images) > 1  # Should have multiple pages

            all_chunks = []
            for image in images:
                qr_strings = qcb.decode_qr_codes_from_image(image)
                for qr_str in qr_strings:
                    chunk = qcb.parse_qr_data(qr_str)
                    if chunk:
                        all_chunks.append(chunk)

            # Reassemble
            file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

            # Write output
            with open(output_file, 'wb') as f:
                f.write(file_data)

            # Verify
            assert filecmp.cmp(input_file, output_file)
            assert len(file_data) == len(test_data)


class TestErrorRecovery:
    """Test error recovery scenarios"""

    def test_recovery_from_missing_chunk(self):
        """Test recovery mode when a chunk is missing"""
        test_data = b"AAAABBBBCCCCDDDD"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'test.bin')

            # Write test file
            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Create chunks
            chunks = qcb.create_chunks(input_file, chunk_size=4, compression='none')
            assert len(chunks) == 4

            # Remove one chunk to simulate missing QR code
            incomplete_chunks = [chunks[0], chunks[1], chunks[3]]  # Missing chunk 2

            # Without recovery mode, should fail
            try:
                qcb.reassemble_chunks(incomplete_chunks, verify=True, recovery_mode=False)
                assert False, "Should have raised ValueError"
            except ValueError:
                pass  # Expected

            # With recovery mode, should succeed with warnings
            file_data, report = qcb.reassemble_chunks(incomplete_chunks, verify=True, recovery_mode=True)

            assert report['missing_pages'] == [3]  # Page 3 is missing
            assert report['found_pages'] == 3
            assert report['total_pages'] == 4


class TestEdgeCases:
    """Test edge cases and unusual scenarios"""

    def test_empty_file(self):
        """Test encoding an empty file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'empty.txt')

            # Create empty file
            Path(input_file).touch()

            # Should be able to encode
            chunks = qcb.create_chunks(input_file, chunk_size=1000, compression='none')

            # Should have at least one chunk (even if empty)
            assert len(chunks) >= 1

    def test_single_byte_file(self):
        """Test encoding a single-byte file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'single.bin')
            pdf_file = os.path.join(tmpdir, 'backup.pdf')
            output_file = os.path.join(tmpdir, 'recovered.bin')

            # Write single byte
            with open(input_file, 'wb') as f:
                f.write(b'X')

            # Encode
            chunks = qcb.create_chunks(input_file, chunk_size=1000, compression='none')
            qr_images = []
            for chunk in chunks:
                img = qcb.create_qr_code(chunk, qr_version=10, error_correction='M')
                qr_images.append(img)

            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=pdf_file,
                title='Single Byte',
                page_size='A4',
                qrs_per_page=(3, 3),
                qr_size_mm=60,
                no_header=False,
                total_pages=len(chunks)
            )

            # Decode
            images = qcb.pdf_to_images(pdf_file)
            all_chunks = []

            for image in images:
                qr_strings = qcb.decode_qr_codes_from_image(image)
                for qr_str in qr_strings:
                    chunk = qcb.parse_qr_data(qr_str)
                    if chunk:
                        all_chunks.append(chunk)

            # Reassemble
            file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

            # Write and verify
            with open(output_file, 'wb') as f:
                f.write(file_data)

            assert filecmp.cmp(input_file, output_file)


class TestDifferentPageSizes:
    """Test PDF generation with different page sizes"""

    def test_different_page_sizes(self):
        """Test that different page sizes all work"""
        test_data = b"Test data for page size testing"

        for page_size in ['A4', 'LETTER', 'LEGAL']:
            with tempfile.TemporaryDirectory() as tmpdir:
                input_file = os.path.join(tmpdir, f'test_{page_size}.txt')
                pdf_file = os.path.join(tmpdir, f'backup_{page_size}.pdf')

                # Write test file
                with open(input_file, 'wb') as f:
                    f.write(test_data)

                # Encode
                chunks = qcb.create_chunks(input_file, chunk_size=1000, compression='none')
                qr_images = []
                for chunk in chunks:
                    img = qcb.create_qr_code(chunk, qr_version=10, error_correction='M')
                    qr_images.append(img)

                qcb.generate_pdf(
                    qr_images=qr_images,
                    output_path=pdf_file,
                    title=f'Test {page_size}',
                    page_size=page_size,
                    qrs_per_page=(3, 3),
                    qr_size_mm=60,
                    no_header=False,
                    total_pages=len(chunks)
                )

                # Verify PDF was created
                assert os.path.exists(pdf_file)
                assert os.path.getsize(pdf_file) > 0


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
