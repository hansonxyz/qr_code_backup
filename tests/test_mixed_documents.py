"""
Integration tests for mixed document detection

These tests verify that PDFs containing pages from multiple
different backups are detected and rejected immediately.
"""

import os
import sys
import tempfile
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qr_code_backup as qcb
from tests.pdf_helpers import merge_pdfs, interleave_pdfs, get_pdf_page_count


class TestMixedDocumentDetection:
    """Integration tests for detecting mixed documents during decoding"""

    def test_mixed_documents_from_different_files(self):
        """Test that mixing pages from two different backups is detected"""
        # Use very different data to ensure different MD5 hashes
        test_data_1 = b"AAAAA First document with unique content 12345 " * 50
        test_data_2 = b"ZZZZZ Second document with totally different data 99999 " * 50

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file_1 = os.path.join(tmpdir, 'file1.bin')
            input_file_2 = os.path.join(tmpdir, 'file2.bin')
            pdf_1 = os.path.join(tmpdir, 'backup1.pdf')
            pdf_2 = os.path.join(tmpdir, 'backup2.pdf')
            mixed_pdf = os.path.join(tmpdir, 'mixed.pdf')

            # Create two different source files
            with open(input_file_1, 'wb') as f:
                f.write(test_data_1)
            with open(input_file_2, 'wb') as f:
                f.write(test_data_2)

            # Encode both files to PDFs
            for input_file, pdf_file in [(input_file_1, pdf_1), (input_file_2, pdf_2)]:
                chunks = qcb.create_chunks(input_file, chunk_size=300, compression='bzip2')
                qr_images = []
                for chunk in chunks:
                    img = qcb.create_qr_code(chunk, qr_version=18, error_correction='M')
                    qr_images.append(img)

                qcb.generate_pdf(
                    qr_images=qr_images,
                    output_path=pdf_file,
                    title='Test',
                    page_width_mm=215.9,
                    page_height_mm=279.4,
                    margin_mm=20,
                    spacing_mm=5,
                    qrs_per_page=(2, 2),
                    qr_size_mm=81.9,
                    no_header=False,
                    total_pages=len(chunks)
                )

            # Merge PDFs (this creates a mixed document)
            merge_pdfs([pdf_1, pdf_2], mixed_pdf)

            # Try to decode the mixed PDF - should fail
            images = qcb.pdf_to_images(mixed_pdf)
            all_chunks = []

            with pytest.raises(Exception) as exc_info:
                # Simulate what decode() command does
                reference_md5 = None
                for image in images:
                    chunk_binaries = qcb.decode_qr_codes_from_image(image)

                    for chunk_binary in chunk_binaries:
                        parsed = qcb.parse_binary_chunk(chunk_binary)
                        if parsed is None:
                            continue

                        if reference_md5 is None:
                            reference_md5 = parsed['md5_hash']
                        else:
                            # Check for mixed document
                            if parsed['md5_hash'] != reference_md5:
                                raise ValueError(
                                    f"Mixed document detected: "
                                    f"Expected MD5 {reference_md5.hex()}, "
                                    f"found {parsed['md5_hash'].hex()}"
                                )

                        all_chunks.append(chunk_binary)

            # Verify error message mentions MD5 mismatch
            assert "Mixed document" in str(exc_info.value) or "MD5" in str(exc_info.value)
            print(f"✓ Mixed document correctly detected and rejected")

    def test_interleaved_pages_from_different_backups(self):
        """Test detection when pages from two backups are interleaved"""
        test_data_1 = b"Document A " * 100
        test_data_2 = b"Document B " * 100

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file_1 = os.path.join(tmpdir, 'fileA.bin')
            input_file_2 = os.path.join(tmpdir, 'fileB.bin')
            pdf_1 = os.path.join(tmpdir, 'backupA.pdf')
            pdf_2 = os.path.join(tmpdir, 'backupB.pdf')
            interleaved_pdf = os.path.join(tmpdir, 'interleaved.pdf')

            # Create two different source files
            with open(input_file_1, 'wb') as f:
                f.write(test_data_1)
            with open(input_file_2, 'wb') as f:
                f.write(test_data_2)

            # Encode both files to PDFs (make sure we get multiple pages)
            for input_file, pdf_file in [(input_file_1, pdf_1), (input_file_2, pdf_2)]:
                chunks = qcb.create_chunks(input_file, chunk_size=200, compression='bzip2')
                qr_images = []
                for chunk in chunks:
                    img = qcb.create_qr_code(chunk, qr_version=18, error_correction='M')
                    qr_images.append(img)

                qcb.generate_pdf(
                    qr_images=qr_images,
                    output_path=pdf_file,
                    title='Test',
                    page_width_mm=215.9,
                    page_height_mm=279.4,
                    margin_mm=20,
                    spacing_mm=5,
                    qrs_per_page=(2, 2),
                    qr_size_mm=81.9,
                    no_header=False,
                    total_pages=len(chunks)
                )

            # Interleave pages from both PDFs
            interleave_pdfs(pdf_1, pdf_2, interleaved_pdf)

            # Try to decode - should detect the mix
            images = qcb.pdf_to_images(interleaved_pdf)

            with pytest.raises(Exception) as exc_info:
                reference_md5 = None
                for image in images:
                    chunk_binaries = qcb.decode_qr_codes_from_image(image)

                    for chunk_binary in chunk_binaries:
                        parsed = qcb.parse_binary_chunk(chunk_binary)
                        if parsed is None:
                            continue

                        if reference_md5 is None:
                            reference_md5 = parsed['md5_hash']
                        else:
                            if parsed['md5_hash'] != reference_md5:
                                raise ValueError(
                                    f"Interleaved pages from different backups detected"
                                )

            assert "different" in str(exc_info.value).lower()
            print(f"✓ Interleaved mixed pages correctly detected")

    def test_single_wrong_page_detected(self):
        """Test that even a single wrong page in a multi-page PDF is detected"""
        test_data_1 = b"Correct document " * 100
        test_data_2 = b"Wrong page content " * 20

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file_1 = os.path.join(tmpdir, 'correct.bin')
            input_file_2 = os.path.join(tmpdir, 'wrong.bin')
            pdf_correct = os.path.join(tmpdir, 'correct.pdf')
            pdf_wrong = os.path.join(tmpdir, 'wrong.pdf')
            mixed_pdf = os.path.join(tmpdir, 'mixed.pdf')

            # Create source files
            with open(input_file_1, 'wb') as f:
                f.write(test_data_1)
            with open(input_file_2, 'wb') as f:
                f.write(test_data_2)

            # Encode both
            for input_file, pdf_file, chunk_size in [
                (input_file_1, pdf_correct, 200),
                (input_file_2, pdf_wrong, 300)
            ]:
                chunks = qcb.create_chunks(input_file, chunk_size=chunk_size, compression='bzip2')
                qr_images = []
                for chunk in chunks:
                    img = qcb.create_qr_code(chunk, qr_version=18, error_correction='M')
                    qr_images.append(img)

                qcb.generate_pdf(
                    qr_images=qr_images,
                    output_path=pdf_file,
                    title='Test',
                    page_width_mm=215.9,
                    page_height_mm=279.4,
                    margin_mm=20,
                    spacing_mm=5,
                    qrs_per_page=(2, 2),
                    qr_size_mm=81.9,
                    no_header=False,
                    total_pages=len(chunks)
                )

            # Get page counts
            correct_pages = get_pdf_page_count(pdf_correct)

            # Merge: most pages from correct PDF, plus one page from wrong PDF
            merge_pdfs([pdf_correct, pdf_wrong], mixed_pdf)

            # Should detect the wrong page
            images = qcb.pdf_to_images(mixed_pdf)

            detected_error = False
            try:
                reference_md5 = None
                for image in images:
                    chunk_binaries = qcb.decode_qr_codes_from_image(image)

                    for chunk_binary in chunk_binaries:
                        parsed = qcb.parse_binary_chunk(chunk_binary)
                        if parsed is None:
                            continue

                        if reference_md5 is None:
                            reference_md5 = parsed['md5_hash']
                        else:
                            if parsed['md5_hash'] != reference_md5:
                                detected_error = True
                                raise ValueError("Single wrong page detected")
            except ValueError:
                detected_error = True

            assert detected_error, "Failed to detect single wrong page"
            print(f"✓ Single wrong page in {correct_pages + 1} pages correctly detected")


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
