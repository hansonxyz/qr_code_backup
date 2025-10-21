"""
Test parity recovery for real-world damage scenarios.

These tests simulate actual physical damage scenarios:
- Entire PDF pages missing (lost pages)
- Partial page damage (coffee spills, torn corners)
- First page damage (critical metadata damage)
"""

import os
import pytest
import tempfile
import filecmp

import qr_code_backup as qcb


class TestParityRecoveryScenarios:
    """Test parity recovery for real-world damage scenarios"""

    def test_recover_from_entire_pdf_page_missing(self):
        """Test recovery when an entire PDF page is missing (4 QR codes at once)."""
        import tempfile
        import filecmp

        # Use random data that won't compress well
        test_data = os.urandom(3000)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            output_file = os.path.join(tmpdir, 'output.bin')

            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with parity (will round to 4 parity QR codes)
            # With chunk_size=100, should create ~30 data chunks
            # At 4 QR codes per page, that's ~8 PDF pages of data
            chunks = qcb.create_chunks(input_file, chunk_size=100, compression='bzip2', parity_percent=5.0)

            parsed_all = [qcb.parse_binary_chunk(c) for c in chunks]
            data_chunks = [i for i, p in enumerate(parsed_all) if not p['is_parity']]

            # Simulate losing an entire PDF page (4 consecutive QR codes)
            # Remove chunks at indices 4, 5, 6, 7 (second PDF page)
            if len(data_chunks) >= 8:
                removed_indices = data_chunks[4:8]  # Remove 4 consecutive chunks
                chunks_with_gaps = [c for i, c in enumerate(chunks) if i not in removed_indices]

                # Decode with recovery
                file_data, report = qcb.reassemble_chunks(chunks_with_gaps)

                with open(output_file, 'wb') as f:
                    f.write(file_data)

                assert filecmp.cmp(input_file, output_file)
                assert report['parity_recovery'] == 4  # Recovered 4 QR codes (1 PDF page)
                print(f"✓ Recovered from entire PDF page missing (4 QR codes)")

    def test_recover_from_partial_page_damage(self):
        """Test recovery when 3 of 4 QR codes on one PDF page are unreadable."""
        import tempfile
        import filecmp

        # Use random data that won't compress well
        test_data = os.urandom(3000)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            output_file = os.path.join(tmpdir, 'output.bin')

            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with parity
            chunks = qcb.create_chunks(input_file, chunk_size=100, compression='bzip2', parity_percent=5.0)

            parsed_all = [qcb.parse_binary_chunk(c) for c in chunks]
            data_chunks = [i for i, p in enumerate(parsed_all) if not p['is_parity']]

            # Simulate partial page damage: 3 of 4 QR codes on one page unreadable
            # Remove chunks 4, 5, 6 (leaving chunk 7 intact)
            if len(data_chunks) >= 8:
                removed_indices = [data_chunks[4], data_chunks[5], data_chunks[6]]
                chunks_with_gaps = [c for i, c in enumerate(chunks) if i not in removed_indices]

                # Decode with recovery
                file_data, report = qcb.reassemble_chunks(chunks_with_gaps)

                with open(output_file, 'wb') as f:
                    f.write(file_data)

                assert filecmp.cmp(input_file, output_file)
                assert report['parity_recovery'] == 3  # Recovered 3 QR codes
                print(f"✓ Recovered from partial page damage (3 of 4 QR codes)")

    def test_recover_from_first_qr_code_damaged(self):
        """Test recovery when the first QR code (page 1, contains file size) is damaged.

        With enhanced parity metadata, we can now recover page 1!
        """
        import tempfile
        import filecmp

        # Use random data that won't compress well
        test_data = os.urandom(3000)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            output_file = os.path.join(tmpdir, 'output.bin')

            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with parity
            chunks = qcb.create_chunks(input_file, chunk_size=100, compression='bzip2', parity_percent=5.0)

            parsed_all = [qcb.parse_binary_chunk(c) for c in chunks]
            data_chunks = [i for i, p in enumerate(parsed_all) if not p['is_parity']]

            # Remove the FIRST data chunk (page 1 - contains file size metadata)
            removed_idx = data_chunks[0]
            chunks_with_gap = chunks[:removed_idx] + chunks[removed_idx+1:]

            # Decode with recovery - should work now with enhanced parity metadata!
            file_data, report = qcb.reassemble_chunks(chunks_with_gap)

            with open(output_file, 'wb') as f:
                f.write(file_data)

            assert filecmp.cmp(input_file, output_file)
            assert report['parity_recovery'] == 1  # Recovered page 1
            print(f"✓ Recovered from first QR code damaged (page 1)")

    def test_recover_from_page_1_completely_missing(self):
        """Test recovery when page 1 is completely missing (critical metadata).

        With enhanced parity metadata, we can now recover page 1!
        """
        import tempfile
        import filecmp

        # Use random data that won't compress well
        test_data = os.urandom(3000)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            output_file = os.path.join(tmpdir, 'output.bin')

            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with parity (will round to 4 parity QR codes)
            chunks = qcb.create_chunks(input_file, chunk_size=100, compression='bzip2', parity_percent=5.0)

            parsed_all = [qcb.parse_binary_chunk(c) for c in chunks]
            data_chunks = [i for i, p in enumerate(parsed_all) if not p['is_parity']]

            # Remove page 1 completely (first QR code, which has file size)
            removed_idx = data_chunks[0]
            chunks_with_gap = chunks[:removed_idx] + chunks[removed_idx+1:]

            # Decode with recovery - should work now!
            file_data, report = qcb.reassemble_chunks(chunks_with_gap)

            with open(output_file, 'wb') as f:
                f.write(file_data)

            assert filecmp.cmp(input_file, output_file)
            assert report['parity_recovery'] == 1  # Recovered page 1
            print(f"✓ Recovered even with page 1 completely missing")

    def test_recover_from_entire_first_pdf_page_missing(self):
        """Test recovery when the entire first PDF page is missing (4 QR codes including page 1).

        With enhanced parity metadata, we can now recover even when the entire first page is missing!
        """
        import tempfile
        import filecmp

        # Use random data that won't compress well
        test_data = os.urandom(3000)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            output_file = os.path.join(tmpdir, 'output.bin')

            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with parity
            chunks = qcb.create_chunks(input_file, chunk_size=100, compression='bzip2', parity_percent=5.0)

            parsed_all = [qcb.parse_binary_chunk(c) for c in chunks]
            data_chunks = [i for i, p in enumerate(parsed_all) if not p['is_parity']]

            # Remove entire first PDF page (first 4 QR codes)
            if len(data_chunks) >= 4:
                removed_indices = data_chunks[0:4]
                chunks_with_gaps = [c for i, c in enumerate(chunks) if i not in removed_indices]

                # Decode with recovery - should work now!
                file_data, report = qcb.reassemble_chunks(chunks_with_gaps)

                with open(output_file, 'wb') as f:
                    f.write(file_data)

                assert filecmp.cmp(input_file, output_file)
                assert report['parity_recovery'] == 4  # Recovered entire first PDF page
                print(f"✓ Recovered from entire first PDF page missing (including page 1 metadata)")

    def test_recover_from_only_parity_pages(self):
        """Test recovery when ALL data pages are missing - decode from ONLY parity pages.

        This demonstrates the full power of Reed-Solomon erasure codes:
        With N parity chunks, you can recover from ALL N data chunks being missing.

        Uses RFC 1149 example:
        - 4 data chunks (page 1)
        - 4 parity chunks (page 2)
        - Remove ALL data chunks
        - Recover entire document from only parity
        """
        import tempfile
        import filecmp
        import subprocess
        from tests.pdf_helpers import extract_pdf_pages, get_pdf_page_count

        # Use the RFC 1149 example file
        input_file = 'examples/rfc1149.txt'

        if not os.path.exists(input_file):
            pytest.skip("RFC 1149 example file not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, 'output.txt')
            pdf_file = os.path.join(tmpdir, 'rfc1149.pdf')
            parity_only_pdf = os.path.join(tmpdir, 'parity_only.pdf')

            # Encode with default settings using CLI (5% parity)
            result = subprocess.run([
                'python3', 'qr_code_backup.py', 'encode',
                input_file,
                '-o', pdf_file,
                '--parity-percent', '5.0'
            ], capture_output=True, text=True)

            assert result.returncode == 0, f"Encode failed: {result.stderr}"

            # Verify PDF structure: should be 2 pages (4 data QRs + 4 parity QRs)
            page_count = get_pdf_page_count(pdf_file)
            assert page_count == 2, f"Expected 2 PDF pages, got {page_count}"

            # Extract ONLY page 2 (the parity page with 4 parity QR codes)
            extract_pdf_pages(pdf_file, parity_only_pdf, [2])

            # Decode from ONLY parity pages (all 4 data chunks missing!)
            result = subprocess.run([
                'python3', 'qr_code_backup.py', 'decode',
                parity_only_pdf,
                '-o', output_file
            ], capture_output=True, text=True)

            assert result.returncode == 0, f"Decode failed: {result.stderr}"

            # Verify complete recovery
            assert filecmp.cmp(input_file, output_file), "Decoded file doesn't match original"
            assert 'Successfully recovered 4 page(s)!' in result.stdout, "Should report 4 pages recovered"

            print(f"✓ Successfully recovered ENTIRE document from ONLY parity pages!")
            print(f"  - All 4 data chunks were missing")
            print(f"  - Recovered from 4 parity chunks alone")
            print(f"  - Demonstrates full power of Reed-Solomon erasure codes")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
