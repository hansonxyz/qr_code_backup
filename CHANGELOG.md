# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-01-21

### Added
- **Parity Pages for Recovery**: Reed-Solomon erasure codes for automatic recovery from missing pages
  - Always enabled by default at 5% overhead
  - Percentage-based parity calculation: `parity_pages = ceil(parity_percent × data_pages)`
  - `--parity-percent` option to adjust recovery overhead (0-100)
  - Can recover any missing pages up to the parity count
  - Works with both encrypted and unencrypted backups
- **Password-Based Encryption**: Military-grade encryption for sensitive data
  - AES-256-GCM authenticated encryption (quantum-resistant)
  - Argon2id key derivation (memory-hard, GPU/ASIC resistant)
  - BLAKE2b password verification (fast pre-check before decryption)
  - `--encrypt` flag to enable encryption during encode
  - Hardcoded secure defaults: time_cost=3, memory=64MB, parallelism=4
- **Order-Independent Decoding**: Scan pages in any order, automatic reordering
  - Pages automatically sorted by embedded page numbers
  - No need to scan pages in sequence
  - Clear feedback when pages are reordered
- **Mixed Document Detection**: Prevents accidental page mixing from different backups
  - MD5-based document validation across all pages
  - Immediate error if pages from different backups are scanned together
  - Shows which PDF page contains the wrong QR code
- **Binary Chunk Format**: Efficient binary metadata format replacing JSON
  - Reduces overhead per QR code
  - Supports encryption metadata (salt, nonce, Argon2 parameters)
  - Supports parity metadata (parity index, total parity/data pages)
  - Backward compatible with unencrypted format
- **Comprehensive Test Suite**: 45 tests covering all features
  - 16 encryption tests (key derivation, encryption/decryption, integration)
  - 19 parity tests (calculation, generation, recovery, integration)
  - 3 order independence tests
  - 3 mixed document detection tests
  - 4 combined feature tests

### Changed
- **Simplified CLI**: Reduced from 14 options to 6 essential options with opinionated defaults
  - Renamed `--module-size` to `--density` (more intuitive)
  - Removed `--page-width` and `--page-height` (hardcoded US Letter: 215.9×279.4mm)
  - Removed `--margin` and `--spacing` (hardcoded at 20mm and 5mm)
  - Removed `--no-header` (headers always enabled)
  - Removed `--argon2-time`, `--argon2-memory`, `--argon2-parallelism` (hardcoded secure defaults)
  - Philosophy: "tar for paper archives" with good defaults, not every knob exposed
- **Parity Always On**: Changed from opt-in to always enabled by default
  - Default 5% overhead provides automatic recovery without user intervention
  - Can be disabled with `--parity-percent 0` if needed
- **Updated Documentation**: Comprehensive README.md for open source release
  - Overview and practical use cases
  - Extensive FAQ covering all features
  - Installation instructions for all platforms
  - Basic and advanced usage examples
  - Troubleshooting guide
  - Performance benchmarks
  - Best practices

### Fixed
- Parity percentage calculation edge cases (ceiling function ensures minimum 1 page when needed)
- Test coverage for various parity percentages and missing page scenarios

### Security
- Encryption implementation uses industry-standard cryptographic libraries
- Argon2id parameters hardcoded to secure defaults (prevents weak configurations)
- Constant-time password comparison prevents timing attacks
- Authenticated encryption (GCM) automatically detects tampering
- Password never stored, only verification hash (BLAKE2b)

## [1.0.0] - 2024-01-15

### Added
- Initial release
- Encode any file to QR code PDF
- Decode QR code PDF back to original file
- Support for all QR error correction levels (L, M, Q, H)
- bzip2 compression to maximize storage efficiency
- MD5 checksum verification for data integrity
- Recovery mode for damaged backups
- Configurable QR code density and grid layout
- Professional PDF output with headers and page numbers
- Info command to view backup metadata
- Comprehensive test suite

### Features
- Multi-page PDF generation with QR codes in 2×2 grid
- Automatic QR version calculation based on data size
- Command-line interface using Click framework
- Cross-platform support (Linux, macOS, Windows)
- Detailed error messages and user feedback
- Support for binary and text files

---

## Version Format

This project uses [Semantic Versioning](https://semver.org/):
- **MAJOR** version for incompatible API/format changes
- **MINOR** version for new functionality in a backward compatible manner
- **PATCH** version for backward compatible bug fixes

## Links

- [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
- [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
