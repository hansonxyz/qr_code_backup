"""
Integration tests for order-independent decoding

These tests verify that PDFs can be decoded successfully
even when pages are in wrong order.
"""

import os
import sys
import tempfile
import filecmp

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qr_code_backup as qcb
from tests.pdf_helpers import reverse_pdf_pages, shuffle_pdf_pages, interleave_pdfs, get_pdf_page_count


class TestOrderIndependentDecoding:
    """Integration tests for order-independent page decoding"""

    def test_decode_reversed_pdf_pages(self):
        """Test decoding PDF with pages in reverse order"""
        test_data = b"Test data for reverse page order validation" * 20

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'test.bin')
            normal_pdf = os.path.join(tmpdir, 'normal.pdf')
            reversed_pdf = os.path.join(tmpdir, 'reversed.pdf')
            output_file = os.path.join(tmpdir, 'recovered.bin')

            # Write test file
            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode normally using CLI (via encode function)
            chunks = qcb.create_chunks(input_file, chunk_size=300, compression='bzip2')

            # Generate QR codes
            qr_images = []
            for chunk in chunks:
                img = qcb.create_qr_code(chunk, qr_version=18, error_correction='M')
                qr_images.append(img)

            # Generate PDF
            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=normal_pdf,
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

            # Reverse the PDF pages
            reverse_pdf_pages(normal_pdf, reversed_pdf)

            # Decode the reversed PDF
            images = qcb.pdf_to_images(reversed_pdf)
            all_chunks = []

            for image in images:
                chunk_binaries = qcb.decode_qr_codes_from_image(image)
                all_chunks.extend(chunk_binaries)

            # Reassemble
            file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

            # Write output
            with open(output_file, 'wb') as f:
                f.write(file_data)

            # Verify files match
            assert filecmp.cmp(input_file, output_file)
            print(f"✓ Successfully decoded {len(images)} pages in reverse order")

    def test_decode_shuffled_pdf_pages(self):
        """Test decoding PDF with randomly shuffled pages"""
        test_data = b"Random shuffle test data " * 30

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'test.bin')
            normal_pdf = os.path.join(tmpdir, 'normal.pdf')
            shuffled_pdf = os.path.join(tmpdir, 'shuffled.pdf')
            output_file = os.path.join(tmpdir, 'recovered.bin')

            # Write test file
            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode
            chunks = qcb.create_chunks(input_file, chunk_size=250, compression='bzip2')

            qr_images = []
            for chunk in chunks:
                img = qcb.create_qr_code(chunk, qr_version=18, error_correction='M')
                qr_images.append(img)

            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=normal_pdf,
                title='Shuffle Test',
                page_width_mm=215.9,
                page_height_mm=279.4,
                margin_mm=20,
                spacing_mm=5,
                qrs_per_page=(2, 2),
                qr_size_mm=81.9,
                no_header=False,
                total_pages=len(chunks)
            )

            # Shuffle pages (e.g., for 3 pages: 0,1,2 -> 2,0,1)
            num_pages = get_pdf_page_count(normal_pdf)
            if num_pages >= 3:
                # Shuffle: move last to first
                page_order = [num_pages-1] + list(range(num_pages-1))
                shuffle_pdf_pages(normal_pdf, shuffled_pdf, page_order)
            else:
                # Not enough pages to shuffle, just copy
                shuffle_pdf_pages(normal_pdf, shuffled_pdf, list(range(num_pages)))

            # Decode
            images = qcb.pdf_to_images(shuffled_pdf)
            all_chunks = []

            for image in images:
                chunk_binaries = qcb.decode_qr_codes_from_image(image)
                all_chunks.extend(chunk_binaries)

            file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

            with open(output_file, 'wb') as f:
                f.write(file_data)

            assert filecmp.cmp(input_file, output_file)
            print(f"✓ Successfully decoded {num_pages} shuffled pages")

    def test_decode_interleaved_scan(self):
        """Test decoding pages scanned in two batches (odd then even)"""
        test_data = b"Interleaved batch test " * 50

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'test.bin')
            pdf_file = os.path.join(tmpdir, 'backup.pdf')
            output_file = os.path.join(tmpdir, 'recovered.bin')

            # Write test file
            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode (should create multiple pages)
            chunks = qcb.create_chunks(input_file, chunk_size=200, compression='bzip2')

            qr_images = []
            for chunk in chunks:
                img = qcb.create_qr_code(chunk, qr_version=18, error_correction='M')
                qr_images.append(img)

            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=pdf_file,
                title='Interleave Test',
                page_width_mm=215.9,
                page_height_mm=279.4,
                margin_mm=20,
                spacing_mm=5,
                qrs_per_page=(2, 2),
                qr_size_mm=81.9,
                no_header=False,
                total_pages=len(chunks)
            )

            num_pages = get_pdf_page_count(pdf_file)

            # Create interleaved order (odd pages first, then even)
            # E.g., [0,1,2,3,4,5] -> [0,2,4,1,3,5]
            if num_pages >= 4:
                odd_indices = [i for i in range(num_pages) if i % 2 == 0]
                even_indices = [i for i in range(num_pages) if i % 2 == 1]
                page_order = odd_indices + even_indices

                interleaved_pdf = os.path.join(tmpdir, 'interleaved.pdf')
                shuffle_pdf_pages(pdf_file, interleaved_pdf, page_order)
                decode_pdf = interleaved_pdf
            else:
                decode_pdf = pdf_file

            # Decode
            images = qcb.pdf_to_images(decode_pdf)
            all_chunks = []

            for image in images:
                chunk_binaries = qcb.decode_qr_codes_from_image(image)
                all_chunks.extend(chunk_binaries)

            file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

            with open(output_file, 'wb') as f:
                f.write(file_data)

            assert filecmp.cmp(input_file, output_file)
            print(f"✓ Successfully decoded {num_pages} interleaved pages")


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
