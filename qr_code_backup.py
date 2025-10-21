#!/usr/bin/env python3
"""
QR Code Backup Tool - Archive data as printable QR codes for long-term offline storage

This tool encodes files into multi-page PDF documents containing QR codes with error
correction, and can decode scanned PDFs back into the original files.

REQUIREMENTS:
  Python 3.8+

  Install Python dependencies with:
    pip install -r requirements.txt

  System dependencies (for pyzbar):
    - Linux: sudo apt-get install libzbar0
    - macOS: brew install zbar
    - Windows: Download from http://zbar.sourceforge.net/

USAGE:
  Encode a file:
    python qr_code_backup.py encode myfile.txt -o output.pdf

  Decode a scanned PDF:
    python qr_code_backup.py decode scanned.pdf -o recovered.txt

  View PDF metadata:
    python qr_code_backup.py info output.pdf

For detailed help on each command:
    python qr_code_backup.py encode --help
    python qr_code_backup.py decode --help
    python qr_code_backup.py info --help
"""

import sys
import os
import json
import hashlib
import base64
import gzip
import bz2
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import io

import click
import qrcode
from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H
from PIL import Image
from reportlab.lib.pagesizes import A4, LETTER, LEGAL
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas as pdf_canvas
from pyzbar import pyzbar
import cv2
import numpy as np
from pypdf import PdfReader, PdfWriter

# Version and format constants
VERSION = "1.0.0"
FORMAT_VERSION = "1.0"

# QR Code error correction mapping
ERROR_CORRECTION_LEVELS = {
    'L': ERROR_CORRECT_L,  # ~7% error correction
    'M': ERROR_CORRECT_M,  # ~15% error correction (default)
    'Q': ERROR_CORRECT_Q,  # ~25% error correction
    'H': ERROR_CORRECT_H,  # ~30% error correction
}

# Page size mapping
PAGE_SIZES = {
    'A4': A4,
    'LETTER': LETTER,
    'LEGAL': LEGAL,
}


# ============================================================================
# ENCODING FUNCTIONS
# ============================================================================

def calculate_checksum(data: bytes, algorithm: str = 'sha256') -> str:
    """Calculate hash checksum of data.

    Args:
        data: Bytes to hash
        algorithm: Hash algorithm (sha256, md5)

    Returns:
        Hex string of hash
    """
    if algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def compress_data(data: bytes, compression: str) -> bytes:
    """Compress data using specified algorithm.

    Args:
        data: Data to compress
        compression: Algorithm - 'none', 'gzip', 'bzip2'

    Returns:
        Compressed data (or original if compression='none')
    """
    if compression == 'none':
        return data
    elif compression == 'gzip':
        return gzip.compress(data)
    elif compression == 'bzip2':
        return bz2.compress(data)
    else:
        raise ValueError(f"Unsupported compression: {compression}")


def decompress_data(data: bytes, compression: str) -> bytes:
    """Decompress data using specified algorithm.

    Args:
        data: Data to decompress
        compression: Algorithm - 'none', 'gzip', 'bzip2'

    Returns:
        Decompressed data (or original if compression='none')
    """
    if compression == 'none':
        return data
    elif compression == 'gzip':
        return gzip.decompress(data)
    elif compression == 'bzip2':
        return bz2.decompress(data)
    else:
        raise ValueError(f"Unsupported compression: {compression}")


def get_qr_modules(qr_version: int) -> int:
    """Get the number of modules (pixels) per side for a QR code version.

    Args:
        qr_version: QR code version (1-40)

    Returns:
        Number of modules per side
    """
    # QR code formula: modules = 4 * version + 17
    return 4 * qr_version + 17


def calculate_qr_physical_size(qr_version: int, module_size_mm: float, border: int = 1) -> float:
    """Calculate the physical size of a QR code.

    Args:
        qr_version: QR code version
        module_size_mm: Size of each module in millimeters
        border: Border size in modules (default: 4)

    Returns:
        Physical size in millimeters
    """
    modules = get_qr_modules(qr_version)
    # Add border on each side
    total_modules = modules + 2 * border
    return total_modules * module_size_mm


def calculate_grid_layout(page_width_mm: float, page_height_mm: float,
                         qr_size_mm: float, margin_mm: float, spacing_mm: float,
                         header_height_mm: float) -> Tuple[int, int]:
    """Calculate optimal grid layout (rows, columns) for QR codes.

    Args:
        page_width_mm: Page width in millimeters
        page_height_mm: Page height in millimeters
        qr_size_mm: QR code size in millimeters
        margin_mm: Page margin in millimeters
        spacing_mm: Spacing between QR codes in millimeters
        header_height_mm: Header height in millimeters (0 if no header)

    Returns:
        Tuple of (rows, columns)
    """
    # Calculate available space
    available_width = page_width_mm - 2 * margin_mm
    available_height = page_height_mm - 2 * margin_mm - header_height_mm

    # Calculate how many QR codes fit
    # Formula: floor((available + spacing) / (qr_size + spacing))
    # The +spacing accounts for the fact that the last QR code doesn't need trailing spacing
    cols = max(1, int((available_width + spacing_mm) / (qr_size_mm + spacing_mm)))
    rows = max(1, int((available_height + spacing_mm) / (qr_size_mm + spacing_mm)))

    return (rows, cols)


def calculate_optimal_qr_version(module_size_mm: float, page_width_mm: float,
                                 page_height_mm: float, margin_mm: float,
                                 spacing_mm: float, header_height_mm: float,
                                 min_qr_codes_per_page: int = 4) -> int:
    """Calculate the optimal QR version that fits the desired grid layout.

    Finds the largest QR code version that still allows at least min_qr_codes_per_page
    to fit on a page (typically 4 for a 2x2 grid).

    Args:
        module_size_mm: Size of each QR module in millimeters
        page_width_mm: Page width in millimeters
        page_height_mm: Page height in millimeters
        margin_mm: Page margin in millimeters
        spacing_mm: Spacing between QR codes in millimeters
        header_height_mm: Header height in millimeters
        min_qr_codes_per_page: Minimum QR codes that must fit per page (default: 4)

    Returns:
        Optimal QR code version (1-40)
    """
    # Try versions from largest (40) down to smallest (1)
    for version in range(40, 0, -1):
        qr_size = calculate_qr_physical_size(version, module_size_mm)
        rows, cols = calculate_grid_layout(page_width_mm, page_height_mm, qr_size,
                                          margin_mm, spacing_mm, header_height_mm)
        qr_codes_per_page = rows * cols

        # If this version fits at least the minimum, use it
        if qr_codes_per_page >= min_qr_codes_per_page:
            return version

    # Fallback to version 1 if nothing fits
    return 1


def get_qr_capacity(qr_version: int, error_correction: str) -> int:
    """Estimate maximum bytes that can fit in a QR code.

    This is an approximation. Actual capacity depends on data content.
    Binary mode capacities for different versions and error correction levels.

    Args:
        qr_version: QR code version (1-40)
        error_correction: Error correction level ('L', 'M', 'Q', 'H')

    Returns:
        Approximate capacity in bytes
    """
    # Simplified capacity table for binary mode
    # Format: {version: {error_level: bytes}}
    # Full table would be very long, so we use a formula approximation
    base_capacities = {
        1: {'L': 17, 'M': 14, 'Q': 11, 'H': 7},
        5: {'L': 108, 'M': 86, 'Q': 62, 'H': 46},
        10: {'L': 346, 'M': 271, 'Q': 213, 'H': 151},
        15: {'L': 682, 'M': 530, 'Q': 406, 'H': 304},
        20: {'L': 1085, 'M': 845, 'Q': 647, 'H': 485},
        25: {'L': 1596, 'M': 1258, 'Q': 938, 'H': 1046},
        30: {'L': 2306, 'M': 1628, 'Q': 1226, 'H': 904},
        40: {'L': 2953, 'M': 2331, 'Q': 1663, 'H': 1273},
    }

    # Find closest version in table
    if qr_version in base_capacities:
        return base_capacities[qr_version][error_correction]

    # Linear interpolation for versions not in table
    versions = sorted(base_capacities.keys())
    for i in range(len(versions) - 1):
        if versions[i] <= qr_version <= versions[i+1]:
            v1, v2 = versions[i], versions[i+1]
            c1 = base_capacities[v1][error_correction]
            c2 = base_capacities[v2][error_correction]
            # Linear interpolation
            ratio = (qr_version - v1) / (v2 - v1)
            return int(c1 + (c2 - c1) * ratio)

    # Fallback for version 1 or 40+
    if qr_version < 1:
        return base_capacities[1][error_correction]
    else:
        return base_capacities[40][error_correction]


def calculate_chunk_size(qr_version: int, error_correction: str) -> int:
    """Calculate optimal data chunk size per QR code.

    Accounts for JSON overhead and Base64 encoding.

    Args:
        qr_version: QR code version
        error_correction: Error correction level

    Returns:
        Bytes of raw data per QR code
    """
    qr_capacity = get_qr_capacity(qr_version, error_correction)

    # Account for JSON structure overhead (approximately 200-300 bytes)
    # and Base64 encoding overhead (4/3 expansion)
    json_overhead = 300
    usable_capacity = qr_capacity - json_overhead

    if usable_capacity <= 0:
        raise ValueError(f"QR version {qr_version} too small for metadata overhead")

    # Base64 encoding expands data by 4/3, so reverse that
    chunk_size = int(usable_capacity * 3 / 4)

    return max(chunk_size, 100)  # Minimum 100 bytes per chunk


def create_chunks(file_path: str, chunk_size: int, compression: str = 'gzip') -> List[Dict[str, Any]]:
    """Split file into chunks with metadata.

    Args:
        file_path: Path to file to encode
        chunk_size: Size of each data chunk in bytes
        compression: Compression algorithm to use

    Returns:
        List of chunk dictionaries with metadata
    """
    # Read entire file
    with open(file_path, 'rb') as f:
        file_data = f.read()

    file_name = os.path.basename(file_path)
    file_size = len(file_data)
    file_checksum = calculate_checksum(file_data)

    # Compress if requested
    if compression != 'none':
        click.echo(f"Compressing with {compression}...")
        compressed_data = compress_data(file_data, compression)
        click.echo(f"  Original size: {file_size:,} bytes")
        click.echo(f"  Compressed size: {len(compressed_data):,} bytes ({len(compressed_data)/file_size*100:.1f}%)")
        data_to_chunk = compressed_data
    else:
        data_to_chunk = file_data

    # Split into chunks
    chunks = []
    total_chunks = (len(data_to_chunk) + chunk_size - 1) // chunk_size

    for i in range(total_chunks):
        start = i * chunk_size
        end = min(start + chunk_size, len(data_to_chunk))
        chunk_data = data_to_chunk[start:end]

        chunk_metadata = {
            'format_version': FORMAT_VERSION,
            'file_name': file_name,
            'file_size': file_size,
            'total_pages': total_chunks,
            'page_number': i + 1,  # 1-indexed
            'chunk_size': len(chunk_data),
            'checksum_type': 'sha256',
            'file_checksum': file_checksum,
            'chunk_checksum': calculate_checksum(chunk_data),
            'compression': compression,
            'data': base64.b64encode(chunk_data).decode('ascii'),
        }

        chunks.append(chunk_metadata)

    return chunks


def create_qr_code(data_dict: Dict[str, Any], qr_version: Optional[int],
                   error_correction: str, box_size: int = 10, border: int = 1) -> Image.Image:
    """Generate QR code image from metadata dictionary.

    Args:
        data_dict: Dictionary to encode
        qr_version: QR code version (None for auto)
        error_correction: Error correction level
        box_size: Size of each QR code box in pixels
        border: Border size in boxes

    Returns:
        PIL Image of QR code
    """
    # Convert dict to JSON string
    json_data = json.dumps(data_dict, separators=(',', ':'))

    # Create QR code
    qr = qrcode.QRCode(
        version=qr_version,
        error_correction=ERROR_CORRECTION_LEVELS[error_correction],
        box_size=box_size,
        border=border,
    )
    qr.add_data(json_data)
    qr.make(fit=True)

    # Create image
    img = qr.make_image(fill_color="black", back_color="white")

    return img


def generate_pdf(qr_images: List[Image.Image], output_path: str, title: str,
                 page_width_mm: float, page_height_mm: float,
                 margin_mm: float, spacing_mm: float,
                 qrs_per_page: Tuple[int, int], qr_size_mm: float,
                 no_header: bool, total_pages: int) -> None:
    """Create multi-page PDF from QR code images.

    Args:
        qr_images: List of PIL Images of QR codes
        output_path: Path for output PDF
        title: Title for headers
        page_width_mm: Page width in millimeters
        page_height_mm: Page height in millimeters
        margin_mm: Page margin in millimeters
        spacing_mm: Spacing between QR codes in millimeters
        qrs_per_page: Tuple of (rows, cols)
        qr_size_mm: Size of each QR code in millimeters
        no_header: Skip header if True
        total_pages: Total number of pages for header
    """
    # Convert mm to points (ReportLab uses points)
    page_width = page_width_mm * mm
    page_height = page_height_mm * mm
    margin = margin_mm * mm
    spacing = spacing_mm * mm
    qr_size = qr_size_mm * mm

    c = pdf_canvas.Canvas(output_path, pagesize=(page_width, page_height))

    rows, cols = qrs_per_page
    qrs_on_page = rows * cols

    header_height = 40 * mm if not no_header else 0

    total_pdf_pages = (len(qr_images) + qrs_on_page - 1) // qrs_on_page

    # Calculate horizontal centering offset
    grid_width = cols * qr_size + (cols - 1) * spacing
    available_width = page_width - 2 * margin
    horizontal_offset = (available_width - grid_width) / 2

    for page_idx in range(total_pdf_pages):
        # Draw header
        if not no_header:
            c.setFont("Helvetica-Bold", 14)
            c.drawString(margin, page_height - margin - 5*mm, "QR Code Backup Archive")

            c.setFont("Helvetica", 10)
            c.drawString(margin, page_height - margin - 12*mm, f"Title: {title}")
            c.drawString(margin, page_height - margin - 18*mm,
                        f"Page {page_idx + 1} of {total_pdf_pages}")
            c.drawString(margin, page_height - margin - 24*mm,
                        "Decode with: qr_code_backup decode")

            # Draw line
            c.line(margin, page_height - margin - 28*mm,
                  page_width - margin, page_height - margin - 28*mm)

        # Draw QR codes in grid
        start_idx = page_idx * qrs_on_page
        end_idx = min(start_idx + qrs_on_page, len(qr_images))

        for local_idx, qr_idx in enumerate(range(start_idx, end_idx)):
            row = local_idx // cols
            col = local_idx % cols

            x = margin + horizontal_offset + col * (qr_size + spacing)
            y = page_height - header_height - margin - (row + 1) * qr_size - row * spacing

            # Save QR image to temporary buffer
            img_buffer = io.BytesIO()
            qr_images[qr_idx].save(img_buffer, format='PNG')
            img_buffer.seek(0)

            # Draw on PDF using ImageReader
            c.drawImage(ImageReader(img_buffer), x, y, width=qr_size, height=qr_size)

        c.showPage()

    c.save()


# ============================================================================
# DECODING FUNCTIONS
# ============================================================================

def pdf_to_images(pdf_path: str) -> List[np.ndarray]:
    """Convert PDF pages to OpenCV images.

    Args:
        pdf_path: Path to PDF file

    Returns:
        List of images as numpy arrays (OpenCV format)
    """
    from pdf2image import convert_from_path

    # Convert PDF to PIL images
    pil_images = convert_from_path(pdf_path, dpi=300)

    # Convert to OpenCV format (numpy arrays)
    cv_images = []
    for pil_img in pil_images:
        # Convert PIL to numpy array (RGB)
        img_array = np.array(pil_img)
        # Convert RGB to BGR for OpenCV
        img_bgr = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
        cv_images.append(img_bgr)

    return cv_images


def decode_qr_codes_from_image(image: np.ndarray) -> List[str]:
    """Find and decode all QR codes in an image.

    Args:
        image: OpenCV image (numpy array)

    Returns:
        List of decoded strings
    """
    # Convert to grayscale for better detection
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Detect and decode QR codes
    decoded_objects = pyzbar.decode(gray)

    results = []
    for obj in decoded_objects:
        # Decode bytes to string
        data = obj.data.decode('utf-8')
        results.append(data)

    return results


def parse_qr_data(qr_string: str) -> Optional[Dict[str, Any]]:
    """Parse JSON metadata from QR code string.

    Args:
        qr_string: Decoded QR code string

    Returns:
        Metadata dictionary or None if parsing fails
    """
    try:
        data = json.loads(qr_string)
        return data
    except json.JSONDecodeError:
        return None


def reassemble_chunks(chunks: List[Dict[str, Any]], verify: bool = True,
                     recovery_mode: bool = False) -> Tuple[bytes, Dict[str, Any]]:
    """Sort, validate, and reassemble chunks into original file.

    Args:
        chunks: List of chunk metadata dictionaries
        verify: Verify checksums if True
        recovery_mode: Attempt recovery even with missing chunks

    Returns:
        Tuple of (file_data, report_dict)

    Raises:
        ValueError: If chunks cannot be reassembled
    """
    if not chunks:
        raise ValueError("No chunks provided")

    # Get metadata from first chunk
    first_chunk = chunks[0]
    file_name = first_chunk['file_name']
    file_size = first_chunk['file_size']
    total_pages = first_chunk['total_pages']
    compression = first_chunk['compression']
    file_checksum = first_chunk['file_checksum']

    # Sort by page number
    chunks_sorted = sorted(chunks, key=lambda x: x['page_number'])

    # Check for missing pages
    page_numbers = [c['page_number'] for c in chunks_sorted]
    expected_pages = set(range(1, total_pages + 1))
    actual_pages = set(page_numbers)
    missing_pages = expected_pages - actual_pages

    report = {
        'total_pages': total_pages,
        'found_pages': len(actual_pages),
        'missing_pages': sorted(missing_pages),
        'checksum_failures': [],
    }

    if missing_pages and not recovery_mode:
        raise ValueError(f"Missing {len(missing_pages)} pages: {sorted(missing_pages)}")

    # Verify chunk checksums
    if verify:
        for chunk in chunks_sorted:
            chunk_data = base64.b64decode(chunk['data'])
            expected_checksum = chunk['chunk_checksum']
            actual_checksum = calculate_checksum(chunk_data)

            if expected_checksum != actual_checksum:
                report['checksum_failures'].append(chunk['page_number'])

    if report['checksum_failures'] and not recovery_mode:
        raise ValueError(f"Chunk checksum failures on pages: {report['checksum_failures']}")

    # Reassemble data
    compressed_data = b''
    for chunk in chunks_sorted:
        chunk_data = base64.b64decode(chunk['data'])
        compressed_data += chunk_data

    # Decompress
    try:
        file_data = decompress_data(compressed_data, compression)
    except Exception as e:
        if not recovery_mode:
            raise ValueError(f"Decompression failed: {e}")
        # In recovery mode, return compressed data
        file_data = compressed_data
        report['decompression_failed'] = True

    # Verify file checksum
    if verify and 'decompression_failed' not in report:
        actual_file_checksum = calculate_checksum(file_data)
        if actual_file_checksum != file_checksum:
            report['file_checksum_mismatch'] = True
            if not recovery_mode:
                raise ValueError("File checksum mismatch - data corrupted")

    report['file_name'] = file_name
    report['file_size'] = file_size
    report['compression'] = compression

    return file_data, report


# ============================================================================
# CLI COMMANDS
# ============================================================================

@click.group()
@click.version_option(version=VERSION)
def cli():
    """QR Code Backup - Archive data as printable QR codes for offline storage.

    This tool encodes files into multi-page PDF documents containing QR codes,
    and can decode scanned PDFs back into the original files.
    """
    pass


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), default=None,
              help='Output PDF path (default: <input_file>.qr.pdf)')
@click.option('--error-correction', type=click.Choice(['L', 'M', 'Q', 'H']), default='M',
              help='Error correction level: L(7%), M(15%), Q(25%), H(30%) [default: M]')
@click.option('--module-size', type=float, default=0.9,
              help='QR module size in millimeters [default: 0.9]')
@click.option('--page-width', type=float, default=215.9,
              help='Page width in millimeters [default: 215.9 (US Letter)]')
@click.option('--page-height', type=float, default=279.4,
              help='Page height in millimeters [default: 279.4 (US Letter)]')
@click.option('--margin', type=float, default=20.0,
              help='Page margin in millimeters [default: 20]')
@click.option('--spacing', type=float, default=5.0,
              help='Spacing between QR codes in millimeters [default: 5]')
@click.option('--title', type=str, default=None,
              help='Title for page headers (default: filename)')
@click.option('--no-header', is_flag=True,
              help='Disable header text on pages')
def encode(input_file, output, error_correction, module_size,
           page_width, page_height, margin, spacing, title, no_header):
    """Encode a file into a QR code backup PDF.

    Example:
        qr_code_backup encode mydata.txt -o backup.pdf
    """
    try:
        # Hardcode compression to bzip2
        compression = 'bzip2'

        # Validate module size and warn if too small
        if module_size < 0.8:
            click.echo(f"\nWARNING: Module size {module_size}mm is below recommended minimum (0.8mm).", err=True)
            click.echo(f"         This density risks data loss when printed and scanned.", err=True)
            click.echo(f"         Consider using --module-size 1.2 or higher for reliable results.\n", err=True)

        # Set defaults
        if output is None:
            output = input_file + '.qr.pdf'
        if title is None:
            title = os.path.basename(input_file)

        # Auto-calculate optimal QR version for 2x2 grid (4 codes per page)
        header_height = 40.0 if not no_header else 0.0
        optimal_version = calculate_optimal_qr_version(
            module_size, page_width, page_height, margin, spacing, header_height,
            min_qr_codes_per_page=4
        )

        # Calculate QR code physical size
        qr_physical_size = calculate_qr_physical_size(optimal_version, module_size)

        # Calculate grid layout
        rows, cols = calculate_grid_layout(page_width, page_height, qr_physical_size,
                                           margin, spacing, header_height)
        qrs_per_page = rows * cols

        # Display configuration
        click.echo(f"\nEncoding: {input_file}")
        click.echo(f"Page: {page_width}mm × {page_height}mm (margin: {margin}mm, spacing: {spacing}mm)")
        click.echo(f"QR Configuration: Version {optimal_version}, Error Correction {error_correction}")
        click.echo(f"QR Module Size: {module_size}mm → Physical QR Size: {qr_physical_size:.1f}mm")
        click.echo(f"Grid Layout: {rows} rows × {cols} columns = {qrs_per_page} QR codes per page")

        # Calculate chunk size
        chunk_size = calculate_chunk_size(optimal_version, error_correction)

        # Create chunks
        click.echo(f"Chunk size: {chunk_size:,} bytes per QR code")
        chunks = create_chunks(input_file, chunk_size, compression)

        # Calculate number of pages needed
        num_pages = (len(chunks) + qrs_per_page - 1) // qrs_per_page
        click.echo(f"QR codes required: {len(chunks)}")
        click.echo(f"PDF pages required: {num_pages}")

        # Generate QR codes
        click.echo("Generating QR codes...")
        qr_images = []
        with click.progressbar(chunks, label='Creating QR codes') as bar:
            for chunk in bar:
                img = create_qr_code(chunk, optimal_version, error_correction)
                qr_images.append(img)

        # Generate PDF
        click.echo("Writing PDF...")
        generate_pdf(qr_images, output, title, page_width, page_height,
                    margin, spacing, (rows, cols), qr_physical_size, no_header, len(chunks))

        # Display summary
        click.echo(f"\nOutput: {output}")
        file_checksum = chunks[0]['file_checksum']
        click.echo(f"Verification hash (SHA-256): {file_checksum}")
        click.echo(f"Store this hash separately to verify successful recovery.")

    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('input_pdf', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), default=None,
              help='Output file path (default: from metadata)')
@click.option('--verify', is_flag=True, default=True,
              help='Verify integrity using checksums [default: enabled]')
@click.option('--recovery-mode', is_flag=True,
              help='Attempt recovery from missing/damaged QR codes')
@click.option('--force', is_flag=True,
              help='Overwrite existing output file')
def decode(input_pdf, output, verify, recovery_mode, force):
    """Decode a QR code backup PDF into original file.

    Example:
        qr_code_backup decode backup.pdf -o recovered.txt
    """
    try:
        click.echo(f"\nDecoding: {input_pdf}")

        # Convert PDF to images
        click.echo("Converting PDF to images...")
        images = pdf_to_images(input_pdf)
        click.echo(f"Found {len(images)} pages")

        # Decode QR codes from all pages
        click.echo("Reading QR codes...")
        all_chunks = []
        qr_count = 0

        with click.progressbar(images, label='Scanning pages') as bar:
            for page_idx, image in enumerate(bar, 1):
                qr_strings = decode_qr_codes_from_image(image)

                for qr_str in qr_strings:
                    chunk = parse_qr_data(qr_str)
                    if chunk:
                        all_chunks.append(chunk)
                        qr_count += 1
                    else:
                        click.echo(f"\nWarning: Page {page_idx} - Failed to parse QR code", err=True)

        click.echo(f"Successfully decoded {qr_count} QR codes from {len(images)} pages")

        if not all_chunks:
            click.echo("Error: No valid QR codes found", err=True)
            sys.exit(1)

        # Reassemble file
        click.echo("Reassembling data...")
        try:
            file_data, report = reassemble_chunks(all_chunks, verify=verify,
                                                 recovery_mode=recovery_mode)
        except ValueError as e:
            click.echo(f"\nError: {e}", err=True)
            if not recovery_mode:
                click.echo("Use --recovery-mode to attempt partial recovery", err=True)
            sys.exit(1)

        # Determine output path
        if output is None:
            output = report['file_name']

        # Check if file exists
        if os.path.exists(output) and not force:
            click.echo(f"\nError: Output file '{output}' already exists. Use --force to overwrite.", err=True)
            sys.exit(1)

        # Write output
        click.echo(f"Decompressing..." if report['compression'] != 'none' else "Writing output...")
        with open(output, 'wb') as f:
            f.write(file_data)

        # Display report
        click.echo(f"\nRecovered: {output} ({len(file_data):,} bytes)")

        if verify:
            if report.get('file_checksum_mismatch'):
                click.echo("Warning: File checksum MISMATCH - data may be corrupted!", err=True)
            elif report.get('decompression_failed'):
                click.echo("Warning: Decompression failed - output may be corrupted!", err=True)
            else:
                click.echo("Verification: PASS (checksum matches)")

        if report['missing_pages']:
            click.echo(f"Warning: Missing {len(report['missing_pages'])} pages: {report['missing_pages']}", err=True)

        if report['checksum_failures']:
            click.echo(f"Warning: Checksum failures on pages: {report['checksum_failures']}", err=True)

    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument('pdf_file', type=click.Path(exists=True))
def info(pdf_file):
    """Display metadata about a QR code backup PDF.

    Example:
        qr_code_backup info backup.pdf
    """
    try:
        click.echo(f"\nReading: {pdf_file}")

        # Convert first page to image
        images = pdf_to_images(pdf_file)
        if not images:
            click.echo("Error: No pages found in PDF", err=True)
            sys.exit(1)

        # Decode QR codes from first page
        qr_strings = decode_qr_codes_from_image(images[0])

        if not qr_strings:
            click.echo("Error: No QR codes found on first page", err=True)
            sys.exit(1)

        # Parse first QR code
        metadata = parse_qr_data(qr_strings[0])

        if not metadata:
            click.echo("Error: Failed to parse QR code metadata", err=True)
            sys.exit(1)

        # Display metadata
        click.echo(f"\n{'='*60}")
        click.echo("QR CODE BACKUP METADATA")
        click.echo(f"{'='*60}")
        click.echo(f"Format Version:      {metadata.get('format_version', 'N/A')}")
        click.echo(f"Original Filename:   {metadata.get('file_name', 'N/A')}")
        click.echo(f"Original File Size:  {metadata.get('file_size', 0):,} bytes")
        click.echo(f"Total Pages:         {metadata.get('total_pages', 'N/A')}")
        click.echo(f"Compression:         {metadata.get('compression', 'N/A')}")
        click.echo(f"Checksum Type:       {metadata.get('checksum_type', 'N/A')}")
        click.echo(f"File Checksum:       {metadata.get('file_checksum', 'N/A')}")
        click.echo(f"QR Codes per Page:   ~{len(qr_strings)}")
        click.echo(f"PDF Pages:           {len(images)}")
        click.echo(f"{'='*60}\n")

    except Exception as e:
        click.echo(f"\nError: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
