"""
Unit tests for parity page functionality

Tests for Reed-Solomon parity generation and recovery.
"""

import os
import sys
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qr_code_backup as qcb


class TestParityCalculation:
    """Tests for parity count calculation (rounded to multiples of 4)"""

    def test_calculate_parity_count_default(self):
        """Test default parity count calculation (5% rounded to multiple of 4)."""
        # All these round to 4 (minimum for complete page)
        assert qcb.calculate_parity_count(1) == 4      # ceil(1 * 0.05) = 1 → rounds to 4
        assert qcb.calculate_parity_count(20) == 4     # ceil(20 * 0.05) = 1 → rounds to 4
        assert qcb.calculate_parity_count(21) == 4     # ceil(21 * 0.05) = 2 → rounds to 4
        assert qcb.calculate_parity_count(40) == 4     # ceil(40 * 0.05) = 2 → rounds to 4
        assert qcb.calculate_parity_count(41) == 4     # ceil(41 * 0.05) = 3 → rounds to 4
        assert qcb.calculate_parity_count(100) == 8    # ceil(100 * 0.05) = 5 → rounds to 8

    def test_calculate_parity_count_custom(self):
        """Test custom parity percentage (rounded to multiple of 4)."""
        assert qcb.calculate_parity_count(10, parity_percent=10.0) == 4   # ceil(10 * 0.10) = 1 → 4
        assert qcb.calculate_parity_count(100, parity_percent=10.0) == 12 # ceil(100 * 0.10) = 10 → 12
        assert qcb.calculate_parity_count(10, parity_percent=0.0) == 0    # Disabled
        assert qcb.calculate_parity_count(100, parity_percent=1.0) == 4   # ceil(100 * 0.01) = 1 → 4
        assert qcb.calculate_parity_count(100, parity_percent=15.0) == 16 # ceil(100 * 0.15) = 15 → 16


class TestChunkPadding:
    """Tests for chunk padding to uniform size"""

    def test_pad_chunks_uniform(self):
        """Test padding chunks to uniform size."""
        chunks = [b"abc", b"abcde", b"a"]
        padded, max_size = qcb.pad_chunks(chunks)

        assert max_size == 5
        assert len(padded) == 3
        assert len(padded[0]) == 5
        assert len(padded[1]) == 5
        assert len(padded[2]) == 5
        assert padded[0] == b"abc\x00\x00"
        assert padded[1] == b"abcde"
        assert padded[2] == b"a\x00\x00\x00\x00"

    def test_pad_chunks_already_uniform(self):
        """Test padding when chunks are already same size."""
        chunks = [b"aaaa", b"bbbb", b"cccc"]
        padded, max_size = qcb.pad_chunks(chunks)

        assert max_size == 4
        assert padded == chunks  # Should be unchanged


class TestParityGeneration:
    """Tests for parity chunk generation"""

    def test_generate_parity_chunks_basic(self):
        """Test basic parity generation."""
        # Create 4 chunks of same size
        data = [b"AAAA", b"BBBB", b"CCCC", b"DDDD"]

        parity = qcb.generate_parity_chunks(data, num_parity=1)

        assert len(parity) == 1
        assert len(parity[0]) == len(data[0])
        assert isinstance(parity[0], bytes)

    def test_generate_parity_chunks_multiple(self):
        """Test generating multiple parity chunks."""
        data = [b"1234", b"5678", b"9ABC", b"DEFG"]

        parity = qcb.generate_parity_chunks(data, num_parity=2)

        assert len(parity) == 2
        assert len(parity[0]) == 4
        assert len(parity[1]) == 4


class TestParityRecovery:
    """Tests for recovering missing chunks using parity"""

    def test_recover_single_missing_chunk(self):
        """Test recovery of single missing chunk."""
        # Create data
        data = [b"AAAA", b"BBBB", b"CCCC", b"DDDD"]

        # Generate parity
        parity = qcb.generate_parity_chunks(data, num_parity=1)

        # Simulate missing chunk 2 (b"CCCC")
        incomplete = [b"AAAA", b"BBBB", None, b"DDDD"]

        # Recover
        recovered = qcb.recover_missing_chunks(incomplete, parity, num_data_chunks=4)

        assert len(recovered) == 4
        assert recovered[2] == b"CCCC"
        assert recovered == data

    def test_recover_multiple_missing_chunks(self):
        """Test recovery of multiple missing chunks."""
        data = [b"AA", b"BB", b"CC", b"DD", b"EE"]

        # Generate 2 parity chunks (can recover up to 2 missing)
        parity = qcb.generate_parity_chunks(data, num_parity=2)

        # Missing 2 chunks
        incomplete = [b"AA", None, b"CC", None, b"EE"]

        recovered = qcb.recover_missing_chunks(incomplete, parity, num_data_chunks=5)

        assert recovered[1] == b"BB"
        assert recovered[3] == b"DD"
        assert recovered == data

    def test_recover_none_missing(self):
        """Test recovery when no chunks are missing (no-op)."""
        data = [b"A1", b"B2", b"C3"]
        parity = qcb.generate_parity_chunks(data, num_parity=1)

        # All chunks present
        recovered = qcb.recover_missing_chunks(data, parity, num_data_chunks=3)

        assert recovered == data

    def test_too_many_missing_chunks(self):
        """Test that recovery fails when too many chunks missing."""
        data = [b"AA", b"BB", b"CC", b"DD"]
        parity = qcb.generate_parity_chunks(data, num_parity=1)

        # Missing 2 chunks, but only 1 parity
        incomplete = [b"AA", None, None, b"DD"]

        with pytest.raises(ValueError, match="Cannot recover"):
            qcb.recover_missing_chunks(incomplete, parity, num_data_chunks=4)

    def test_recover_last_chunk_missing(self):
        """Test edge case: last chunk missing."""
        data = [b"111", b"222", b"333", b"444"]
        parity = qcb.generate_parity_chunks(data, num_parity=1)

        # Last chunk missing
        incomplete = [b"111", b"222", b"333", None]

        recovered = qcb.recover_missing_chunks(incomplete, parity, num_data_chunks=4)

        assert recovered[3] == b"444"
        assert recovered == data


class TestParityMetadataParsing:
    """Tests for parsing parity page metadata"""

    def test_parse_data_page_with_parity_flag(self):
        """Test parsing data page with parity flag = 0x00."""
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

    def test_parse_parity_page_metadata(self):
        """Test parsing parity page with full metadata."""
        import hashlib
        md5 = hashlib.md5(b"data").digest()

        chunk = bytearray()
        chunk.append(0x00)  # Not encrypted
        chunk.extend(md5)
        chunk.extend((21).to_bytes(2, 'big'))  # Page 21 (parity page)
        chunk.append(0x01)  # Parity flag = 0x01 (parity page)
        chunk.extend((0).to_bytes(2, 'big'))  # Parity index 0
        chunk.extend((1).to_bytes(2, 'big'))  # Total parity = 1
        chunk.extend((20).to_bytes(2, 'big'))  # Total data pages = 20
        chunk.extend(b"parity_data_bytes")

        parsed = qcb.parse_binary_chunk(bytes(chunk))

        assert parsed is not None
        assert parsed['page_number'] == 21
        assert parsed['is_parity'] == True
        assert parsed['parity_index'] == 0
        assert parsed['total_parity'] == 1
        assert parsed['total_data'] == 20
        assert parsed['data'] == b"parity_data_bytes"

    def test_parity_page_structure(self):
        """Test parity page metadata byte layout."""
        import hashlib
        md5 = hashlib.md5(b"test_doc").digest()

        chunk = bytearray()
        chunk.append(0x00)  # Encryption flag
        chunk.extend(md5)   # 16 bytes MD5
        chunk.extend((5).to_bytes(2, 'big'))  # Page 5
        chunk.append(0x01)  # Parity flag
        chunk.extend((2).to_bytes(2, 'big'))  # Parity index 2
        chunk.extend((3).to_bytes(2, 'big'))  # Total parity 3
        chunk.extend((4).to_bytes(2, 'big'))  # Total data 4
        chunk.extend(b"XYZ")  # Parity data

        parsed = qcb.parse_binary_chunk(bytes(chunk))

        # Verify structure
        assert len(chunk) == 1 + 16 + 2 + 1 + 2 + 2 + 2 + 3  # 29 bytes total
        assert parsed['parity_index'] == 2
        assert parsed['total_parity'] == 3
        assert parsed['total_data'] == 4


class TestParityIntegration:
    """Integration tests for parity encode-decode-recover cycle"""

    def test_encode_with_parity(self):
        """Test encoding with parity pages."""
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Test data for parity" * 50)
            test_file = f.name

        try:
            # Encode with 5% parity (default)
            chunks = qcb.create_chunks(
                test_file,
                chunk_size=200,
                compression='bzip2',
                parity_percent=5.0
            )

            # Should have data chunks + parity chunks
            data_chunks = [c for c in chunks if qcb.parse_binary_chunk(c)['is_parity'] == False]
            parity_chunks = [c for c in chunks if qcb.parse_binary_chunk(c)['is_parity'] == True]

            assert len(parity_chunks) >= 1  # Should have at least 1 parity page with 5%
            assert len(chunks) == len(data_chunks) + len(parity_chunks)

        finally:
            os.unlink(test_file)

    def test_decode_with_parity_all_present(self):
        """Test decoding when all pages present (parity not needed)."""
        import tempfile
        import filecmp

        test_data = b"Parity test data" * 100

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            output_file = os.path.join(tmpdir, 'output.bin')

            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with parity (5% default)
            chunks = qcb.create_chunks(input_file, chunk_size=250, parity_percent=5.0)

            # Decode with all pages present
            file_data, report = qcb.reassemble_chunks(chunks)

            with open(output_file, 'wb') as f:
                f.write(file_data)

            assert filecmp.cmp(input_file, output_file)
            assert report['parity_recovery'] == 0  # No recovery needed

    def test_recover_from_single_missing_page(self):
        """Test recovering from a single missing data page."""
        import tempfile
        import filecmp

        # Use random data that won't compress well
        test_data = os.urandom(2000)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            output_file = os.path.join(tmpdir, 'output.bin')

            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with 5% parity (small chunks to ensure multiple pages, should give ~1 parity page)
            chunks = qcb.create_chunks(input_file, chunk_size=100, compression='bzip2', parity_percent=5.0)

            # Remove a middle data page (not page 1, not parity)
            parsed_all = [qcb.parse_binary_chunk(c) for c in chunks]
            data_pages = [i for i, p in enumerate(parsed_all) if not p['is_parity']]

            # Remove second data page
            removed_idx = data_pages[1]
            chunks_with_gap = chunks[:removed_idx] + chunks[removed_idx+1:]

            # Decode with recovery
            file_data, report = qcb.reassemble_chunks(chunks_with_gap)

            with open(output_file, 'wb') as f:
                f.write(file_data)

            assert filecmp.cmp(input_file, output_file)
            assert report['parity_recovery'] == 1  # Recovered 1 page

    def test_recover_from_multiple_missing_pages(self):
        """Test recovering from multiple missing pages."""
        import tempfile
        import filecmp

        # Use random data that won't compress well
        test_data = os.urandom(3000)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')
            output_file = os.path.join(tmpdir, 'output.bin')

            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with 10% parity (small chunks to ensure multiple pages, should give ~2-3 parity pages)
            chunks = qcb.create_chunks(input_file, chunk_size=100, compression='bzip2', parity_percent=10.0)

            # Remove 2 data pages
            parsed_all = [qcb.parse_binary_chunk(c) for c in chunks]
            data_pages = [i for i, p in enumerate(parsed_all) if not p['is_parity']]

            # Remove pages 2 and 4
            removed_indices = [data_pages[1], data_pages[3]]
            chunks_with_gaps = [c for i, c in enumerate(chunks) if i not in removed_indices]

            # Decode with recovery
            file_data, report = qcb.reassemble_chunks(chunks_with_gaps)

            with open(output_file, 'wb') as f:
                f.write(file_data)

            assert filecmp.cmp(input_file, output_file)
            assert report['parity_recovery'] == 2  # Recovered 2 pages
            # Verify we had enough parity pages
            parity_chunks = [c for c in chunks if qcb.parse_binary_chunk(c)['is_parity']]
            assert len(parity_chunks) >= 2  # Need at least 2 parity pages to recover 2 missing

    def test_cannot_recover_too_many_missing(self):
        """Test that recovery fails when too many pages missing."""
        import tempfile

        # Use random data that won't compress well
        test_data = os.urandom(2000)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = os.path.join(tmpdir, 'input.bin')

            with open(input_file, 'wb') as f:
                f.write(test_data)

            # Encode with 3% parity (ceil(30 * 0.03) = 1 → rounds to 4 parity pages)
            # So we have 4 parity pages, which can recover up to 4 missing data pages
            chunks = qcb.create_chunks(input_file, chunk_size=100, compression='bzip2', parity_percent=3.0)

            # Remove 5 data pages (more than the 4 parity pages can recover)
            parsed_all = [qcb.parse_binary_chunk(c) for c in chunks]
            data_pages = [i for i, p in enumerate(parsed_all) if not p['is_parity']]

            # Remove 5 data pages to exceed parity capacity
            removed_indices = [data_pages[i] for i in [1, 2, 3, 4, 5]]
            chunks_with_gaps = [c for i, c in enumerate(chunks) if i not in removed_indices]

            # Should fail to recover (5 missing > 4 parity pages)
            with pytest.raises(ValueError, match="Cannot recover"):
                qcb.reassemble_chunks(chunks_with_gaps)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
