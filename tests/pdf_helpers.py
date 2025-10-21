"""
PDF manipulation utilities for testing

These helpers allow us to create various test scenarios by
manipulating PDFs (reversing pages, shuffling, merging, etc.)
"""

from typing import List
from pypdf import PdfReader, PdfWriter


def reverse_pdf_pages(input_pdf: str, output_pdf: str) -> None:
    """Reverse the order of pages in a PDF.

    Args:
        input_pdf: Path to input PDF
        output_pdf: Path to output PDF with reversed pages

    Example:
        Input pages: [1, 2, 3, 4, 5]
        Output pages: [5, 4, 3, 2, 1]
    """
    reader = PdfReader(input_pdf)
    writer = PdfWriter()

    for page in reversed(reader.pages):
        writer.add_page(page)

    with open(output_pdf, 'wb') as f:
        writer.write(f)


def shuffle_pdf_pages(input_pdf: str, output_pdf: str, page_order: List[int]) -> None:
    """Reorder PDF pages according to page_order list.

    Args:
        input_pdf: Path to input PDF
        output_pdf: Path to output PDF with reordered pages
        page_order: List of page indices (0-indexed) in desired order

    Example:
        page_order = [2, 0, 4, 1, 3]  # Pages: 3, 1, 5, 2, 4
    """
    reader = PdfReader(input_pdf)
    writer = PdfWriter()

    for idx in page_order:
        if idx < 0 or idx >= len(reader.pages):
            raise ValueError(f"Invalid page index {idx}, PDF has {len(reader.pages)} pages")
        writer.add_page(reader.pages[idx])

    with open(output_pdf, 'wb') as f:
        writer.write(f)


def merge_pdfs(pdf_list: List[str], output_pdf: str) -> None:
    """Merge multiple PDFs into one.

    Args:
        pdf_list: List of PDF file paths to merge (in order)
        output_pdf: Path to output merged PDF

    Example:
        merge_pdfs(['file1.pdf', 'file2.pdf'], 'merged.pdf')
    """
    writer = PdfWriter()

    for pdf_path in pdf_list:
        reader = PdfReader(pdf_path)
        for page in reader.pages:
            writer.add_page(page)

    with open(output_pdf, 'wb') as f:
        writer.write(f)


def extract_pdf_pages(input_pdf: str, output_pdf: str, page_numbers: List[int]) -> None:
    """Extract specific pages from a PDF.

    Args:
        input_pdf: Path to input PDF
        output_pdf: Path to output PDF with extracted pages
        page_numbers: List of page numbers to extract (1-indexed)

    Example:
        extract_pdf_pages('input.pdf', 'output.pdf', [1, 3, 5])
        # Extracts pages 1, 3, and 5
    """
    reader = PdfReader(input_pdf)
    writer = PdfWriter()

    for page_num in page_numbers:
        if page_num < 1 or page_num > len(reader.pages):
            raise ValueError(f"Invalid page number {page_num}, PDF has {len(reader.pages)} pages")
        writer.add_page(reader.pages[page_num - 1])  # Convert to 0-indexed

    with open(output_pdf, 'wb') as f:
        writer.write(f)


def get_pdf_page_count(pdf_path: str) -> int:
    """Get the number of pages in a PDF.

    Args:
        pdf_path: Path to PDF file

    Returns:
        Number of pages
    """
    reader = PdfReader(pdf_path)
    return len(reader.pages)


def interleave_pdfs(pdf1: str, pdf2: str, output_pdf: str) -> None:
    """Interleave pages from two PDFs.

    Args:
        pdf1: Path to first PDF
        pdf2: Path to second PDF
        output_pdf: Path to output PDF with interleaved pages

    Example:
        PDF1 pages: [A1, A2, A3]
        PDF2 pages: [B1, B2, B3]
        Output: [A1, B1, A2, B2, A3, B3]
    """
    reader1 = PdfReader(pdf1)
    reader2 = PdfReader(pdf2)
    writer = PdfWriter()

    # Interleave pages
    max_pages = max(len(reader1.pages), len(reader2.pages))
    for i in range(max_pages):
        if i < len(reader1.pages):
            writer.add_page(reader1.pages[i])
        if i < len(reader2.pages):
            writer.add_page(reader2.pages[i])

    with open(output_pdf, 'wb') as f:
        writer.write(f)
