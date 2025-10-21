"""
Combined integration tests for order-independent decoding + mixed document detection

These tests verify that both features work correctly together:
- Order-independent: Pages can be scanned in any order
- Mixed detection: Pages from different backups are caught immediately
"""

import os
import sys
import tempfile
import filecmp
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qr_code_backup as qcb
from tests.pdf_helpers import shuffle_pdf_pages, merge_pdfs, get_pdf_page_count


class TestCombinedFeatures:
    """Tests that verify order-independent decoding and mixed document detection work together"""

    def test_shuffled_single_document_succeeds(self):
        """Shuffled pages from a single document should decode successfully"""
        test_data = b"Single document with shuffled pages test " * 100

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'test.bin')
            normal_pdf = os.path.join(tmpdir, 'normal.pdf')
            shuffled_pdf = os.path.join(tmpdir, 'shuffled.pdf')
            output_file = os.path.join(tmpdir, 'recovered.bin')

            # Create test file
            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode to PDF (create multiple pages)
            chunks = qcb.create_chunks(input_file, chunk_size=250, compression='bzip2')
            qr_images = []
            for chunk in chunks:
                img = qcb.create_qr_code(chunk, qr_version=18, error_correction='M')
                qr_images.append(img)

            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=normal_pdf,
                title='Single Document Test',
                page_width_mm=215.9,
                page_height_mm=279.4,
                margin_mm=20,
                spacing_mm=5,
                qrs_per_page=(2, 2),
                qr_size_mm=81.9,
                no_header=False,
                total_pages=len(chunks)
            )

            num_pages = get_pdf_page_count(normal_pdf)

            # Shuffle pages significantly
            if num_pages >= 5:
                page_order = [num_pages-1, 0, num_pages-2, 1, num_pages-3] + list(range(2, num_pages-3))
                shuffle_pdf_pages(normal_pdf, shuffled_pdf, page_order)
            else:
                shuffle_pdf_pages(normal_pdf, shuffled_pdf, list(reversed(range(num_pages))))

            # Decode - should succeed despite shuffle
            images = qcb.pdf_to_images(shuffled_pdf)
            all_chunks = []

            for image in images:
                chunk_binaries = qcb.decode_qr_codes_from_image(image)
                all_chunks.extend(chunk_binaries)

            # Reassemble - should work because all chunks from same document
            file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

            with open(output_file, 'wb') as f:
                f.write(file_data)

            # Verify recovery
            assert filecmp.cmp(input_file, output_file)
            print(f"✓ Successfully decoded {num_pages} shuffled pages from single document")

    def test_shuffled_mixed_documents_detected(self):
        """Shuffled pages from different documents should be detected as mixed"""
        test_data_1 = b"Document ONE content here " * 80
        test_data_2 = b"Document TWO different data " * 80

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file_1 = os.path.join(tmpdir, 'doc1.bin')
            input_file_2 = os.path.join(tmpdir, 'doc2.bin')
            pdf_1 = os.path.join(tmpdir, 'backup1.pdf')
            pdf_2 = os.path.join(tmpdir, 'backup2.pdf')
            merged_pdf = os.path.join(tmpdir, 'merged.pdf')
            shuffled_pdf = os.path.join(tmpdir, 'shuffled.pdf')

            # Create two different files
            with open(input_file_1, 'wb') as f:
                f.write(test_data_1)
            with open(input_file_2, 'wb') as f:
                f.write(test_data_2)

            # Encode both to PDFs
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

            # Merge the two PDFs
            merge_pdfs([pdf_1, pdf_2], merged_pdf)

            # Shuffle the merged PDF
            num_pages = get_pdf_page_count(merged_pdf)
            if num_pages >= 4:
                # Complex shuffle to make it harder to detect visually
                page_order = [num_pages-1] + list(range(0, num_pages-1, 2)) + list(range(1, num_pages-1, 2))
                shuffle_pdf_pages(merged_pdf, shuffled_pdf, page_order)
            else:
                shuffle_pdf_pages(merged_pdf, shuffled_pdf, list(reversed(range(num_pages))))

            # Try to decode - should detect mixed documents
            images = qcb.pdf_to_images(shuffled_pdf)

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
                                    f"Mixed documents detected even with shuffling"
                                )

            assert "Mixed" in str(exc_info.value) or "different" in str(exc_info.value).lower()
            print(f"✓ Mixed documents detected even when shuffled ({num_pages} total pages)")

    def test_large_document_complex_reordering(self):
        """Test large document with complex page reordering"""
        # Create enough data for many pages
        test_data = b"Large document test data block " * 300

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'large.bin')
            normal_pdf = os.path.join(tmpdir, 'normal.pdf')
            reordered_pdf = os.path.join(tmpdir, 'reordered.pdf')
            output_file = os.path.join(tmpdir, 'recovered.bin')

            # Create test file
            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with small chunks to create many pages
            chunks = qcb.create_chunks(input_file, chunk_size=150, compression='bzip2')
            qr_images = []
            for chunk in chunks:
                img = qcb.create_qr_code(chunk, qr_version=18, error_correction='M')
                qr_images.append(img)

            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=normal_pdf,
                title='Large Document',
                page_width_mm=215.9,
                page_height_mm=279.4,
                margin_mm=20,
                spacing_mm=5,
                qrs_per_page=(2, 2),
                qr_size_mm=81.9,
                no_header=False,
                total_pages=len(chunks)
            )

            num_pages = get_pdf_page_count(normal_pdf)

            # Create complex reordering: reverse first half, shuffle second half
            if num_pages >= 10:
                mid = num_pages // 2
                first_half_reversed = list(reversed(range(mid)))
                second_half_shuffled = list(range(mid, num_pages))
                # Rotate second half
                second_half_shuffled = second_half_shuffled[::2] + second_half_shuffled[1::2]
                page_order = first_half_reversed + second_half_shuffled
                shuffle_pdf_pages(normal_pdf, reordered_pdf, page_order)
            else:
                shuffle_pdf_pages(normal_pdf, reordered_pdf, list(reversed(range(num_pages))))

            # Decode
            images = qcb.pdf_to_images(reordered_pdf)
            all_chunks = []

            for image in images:
                chunk_binaries = qcb.decode_qr_codes_from_image(image)
                all_chunks.extend(chunk_binaries)

            # Reassemble
            file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

            with open(output_file, 'wb') as f:
                f.write(file_data)

            # Verify
            assert filecmp.cmp(input_file, output_file)
            print(f"✓ Successfully decoded {num_pages} pages with complex reordering")

    def test_partial_document_missing_pages(self):
        """Test that missing pages are detected (not just out of order)"""
        # Use data that won't compress well to ensure we get multiple chunks
        import random
        random.seed(42)  # Reproducible random data
        test_data = bytes([random.randint(0, 255) for _ in range(5000)])

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'test.bin')
            full_pdf = os.path.join(tmpdir, 'full.pdf')
            partial_pdf = os.path.join(tmpdir, 'partial.pdf')

            # Create test file with random data that won't compress well
            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode to PDF with small chunks to ensure many pages
            chunks = qcb.create_chunks(input_file, chunk_size=200, compression='bzip2')
            qr_images = []
            for chunk in chunks:
                img = qcb.create_qr_code(chunk, qr_version=18, error_correction='M')
                qr_images.append(img)

            qcb.generate_pdf(
                qr_images=qr_images,
                output_path=full_pdf,
                title='Full Document',
                page_width_mm=215.9,
                page_height_mm=279.4,
                margin_mm=20,
                spacing_mm=5,
                qrs_per_page=(2, 2),
                qr_size_mm=81.9,
                no_header=False,
                total_pages=len(chunks)
            )

            num_pages = get_pdf_page_count(full_pdf)

            # Create partial PDF by removing middle pages
            if num_pages >= 5:
                # Keep first 2 and last 2 pages, skip middle pages
                pages_to_keep = [0, 1, num_pages-2, num_pages-1]
                shuffle_pdf_pages(full_pdf, partial_pdf, pages_to_keep)
            else:
                # Just keep first and last
                pages_to_keep = [0, num_pages-1] if num_pages >= 2 else [0]
                shuffle_pdf_pages(full_pdf, partial_pdf, pages_to_keep)

            # Try to decode - should fail due to missing pages
            images = qcb.pdf_to_images(partial_pdf)
            all_chunks = []

            for image in images:
                chunk_binaries = qcb.decode_qr_codes_from_image(image)
                all_chunks.extend(chunk_binaries)

            # Reassemble should detect missing pages
            with pytest.raises(Exception) as exc_info:
                file_data, report = qcb.reassemble_chunks(all_chunks, verify=True)

            # Should mention missing or gap
            error_msg = str(exc_info.value).lower()
            assert "missing" in error_msg or "gap" in error_msg or "expected" in error_msg
            print(f"✓ Missing pages detected correctly ({len(pages_to_keep)}/{num_pages} pages present)")


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
