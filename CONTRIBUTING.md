# Contributing to QR Code Backup

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Types of Contributions

We welcome many types of contributions:

- **🐛 Bug Reports**: Found a bug? Let us know!
- **✨ Feature Requests**: Have an idea? Share it!
- **📝 Documentation**: Improve docs, fix typos, add examples
- **🧪 Tests**: Add test coverage, improve test quality
- **💻 Code**: Fix bugs, implement features, optimize performance
- **🎨 Examples**: Add example use cases
- **🔍 Code Review**: Review pull requests

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip package manager
- git

### Fork and Clone

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/qr-code-backup.git
   cd qr-code-backup
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/qr-code-backup.git
   ```

### Install Dependencies

Install system dependencies:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libzbar0 poppler-utils
```

**macOS:**
```bash
brew install zbar poppler
```

Install Python dependencies:
```bash
pip install -r requirements.txt
```

### Run Tests

Verify your setup:
```bash
pytest tests/ -v
```

All 45 tests should pass ✅

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some modifications:

- **Line length**: 100 characters (not 79)
- **Docstrings**: Use Google-style docstrings
- **Type hints**: Encouraged for function signatures
- **Naming**:
  - Functions/variables: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_SNAKE_CASE`

### Code Organization

```python
# Good example
def encode_file(file_path: str, encrypt: bool = False,
                parity_percent: float = 5.0) -> List[bytes]:
    """
    Encode a file into QR code chunks.

    Args:
        file_path: Path to input file
        encrypt: Enable encryption
        parity_percent: Parity percentage (0-100)

    Returns:
        List of binary chunks ready for QR encoding

    Raises:
        FileNotFoundError: If file_path doesn't exist
        ValueError: If parity_percent is invalid
    """
    # Implementation...
```

### Docstring Style

Use Google-style docstrings:

```python
def function_name(param1: str, param2: int) -> bool:
    """
    Brief one-line description.

    More detailed description if needed. Can span multiple lines.
    Explain what the function does, not how it does it.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When this happens
        TypeError: When that happens

    Example:
        >>> function_name("test", 42)
        True
    """
```

### Comments

- Use comments sparingly - prefer self-documenting code
- Explain **why**, not **what**
- Update comments when code changes

```python
# Bad
i = i + 1  # Increment i

# Good
# Adjust for 1-based page numbering in PDF output
page_number = page_index + 1
```

## Testing Guidelines

### Test Structure

- All tests go in `tests/` directory
- Use pytest framework
- One test file per module/feature
- Test classes group related tests

### Writing Tests

```python
import pytest
import qr_code_backup as qcb


class TestFeatureName:
    """Tests for feature_name functionality"""

    def test_basic_case(self):
        """Test basic functionality."""
        result = qcb.some_function("input")
        assert result == "expected"

    def test_edge_case(self):
        """Test edge case handling."""
        with pytest.raises(ValueError, match="error message"):
            qcb.some_function(None)

    def test_integration(self):
        """Test integration with other components."""
        # Create test data
        # Run function
        # Verify results
```

### Test Coverage

- Aim for **>90% code coverage**
- All new features must include tests
- Bug fixes should include regression tests
- Run coverage report:
  ```bash
  pytest --cov=qr_code_backup tests/
  ```

### Test Categories

- **Unit tests**: Test individual functions in isolation
- **Integration tests**: Test feature combinations (encode → decode cycles)
- **Edge cases**: Test boundary conditions, error handling
- **Regression tests**: Test that bugs stay fixed

## Pull Request Process

### Before You Start

1. **Check existing issues**: Is someone already working on this?
2. **Create an issue**: Discuss large changes before implementing
3. **Create a branch**: Use descriptive names
   ```bash
   git checkout -b feature/add-svg-export
   git checkout -b fix/decode-crash-on-invalid-qr
   ```

### Development Workflow

1. **Make your changes**:
   - Write code following style guide
   - Add/update tests
   - Update documentation
   - Add entry to CHANGELOG.md (under "Unreleased")

2. **Test thoroughly**:
   ```bash
   # Run all tests
   pytest tests/ -v

   # Run with coverage
   pytest --cov=qr_code_backup tests/

   # Test specific file
   pytest tests/test_encryption.py -v
   ```

3. **Update documentation**:
   - Update README.md if needed
   - Update docstrings
   - Add examples if applicable

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Add feature: SVG export support"
   ```

   **Commit message format**:
   ```
   Short summary (50 chars or less)

   More detailed explanation if needed. Wrap at 72 characters.
   Explain what changed and why, not how.

   - Bullet points are fine
   - Reference issues: Fixes #123, Relates to #456
   ```

5. **Keep your fork updated**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

6. **Push to your fork**:
   ```bash
   git push origin feature/add-svg-export
   ```

### Submitting the PR

1. **Open Pull Request** on GitHub

2. **Fill out the PR template** completely

3. **Ensure CI passes**: All automated tests must pass

4. **Respond to reviews**: Address feedback promptly

5. **Update PR as needed**: Make requested changes

### PR Checklist

Before submitting, ensure:

- [ ] Code follows style guide
- [ ] All tests pass (`pytest tests/ -v`)
- [ ] New tests added for new functionality
- [ ] Documentation updated (README, docstrings)
- [ ] CHANGELOG.md updated
- [ ] No merge conflicts with main branch
- [ ] Commits are clean and descriptive
- [ ] PR description explains what/why

### PR Review Process

1. **Automated checks** run (CI tests, linting)
2. **Maintainer review** (code quality, design, tests)
3. **Feedback/changes** requested if needed
4. **Approval** once everything looks good
5. **Merge** by maintainer

## Reporting Bugs

### Before Reporting

- **Search existing issues**: Has this been reported?
- **Test with latest version**: Is it still a bug?
- **Minimal reproduction**: Can you reproduce it reliably?

### Bug Report Template

Use the GitHub issue template. Include:

- **Summary**: Brief description of the bug
- **Steps to reproduce**: Exact steps to trigger the bug
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Environment**:
  - OS (Ubuntu 22.04, macOS 14, Windows 11)
  - Python version (3.8, 3.10, 3.12)
  - Tool version (2.0.0)
- **Logs/screenshots**: Error messages, stack traces
- **Sample files** (if relevant): Minimal test case

**Example**:
```markdown
## Bug: Decode fails on encrypted PDFs with long passwords

**Steps to reproduce**:
1. Encode file with 64-character password: `python qr_code_backup.py encode test.txt --encrypt`
2. Enter password: `aaaaaa...` (64 'a's)
3. Decode: `python qr_code_backup.py decode test.txt.qr.pdf -o out.txt`
4. Enter same password

**Expected**: File decodes successfully

**Actual**: Error "Incorrect password" even though password is correct

**Environment**:
- Ubuntu 22.04
- Python 3.10.12
- QR Code Backup 2.0.0

**Error log**:
```
ValueError: Incorrect password
  at decrypt_data (qr_code_backup.py:245)
```
```

## Suggesting Enhancements

### Before Suggesting

- **Check existing requests**: Has this been suggested?
- **Consider scope**: Does it fit the project's goals?
- **Think about use cases**: Who would benefit?

### Feature Request Template

Use the GitHub issue template. Include:

- **Problem**: What problem does this solve?
- **Proposed solution**: How would it work?
- **Alternatives**: Other ways to solve this?
- **Use cases**: Real-world scenarios
- **Impact**: Who benefits? Breaking changes?

**Example**:
```markdown
## Feature Request: Export QR codes as SVG

**Problem**:
PDFs are great for printing, but developers want SVG for web integration.

**Proposed solution**:
Add `--format svg` option to encode command:
```bash
python qr_code_backup.py encode file.txt --format svg -o output/
```
Creates `output/page_001.svg`, `output/page_002.svg`, etc.

**Alternatives**:
- PNG export (but SVG is vector, scales better)
- HTML export with embedded QR codes

**Use cases**:
- Embedding QR codes in web pages
- Generating high-res QRs for large format printing
- Archiving in vector format

**Impact**:
- Benefits developers integrating with web apps
- No breaking changes (new optional feature)
- Requires adding svgwrite dependency
```

## Areas for Contribution

We especially welcome contributions in these areas:

### High Priority
- **Performance optimization**: Faster encoding/decoding
- **Error handling**: Better error messages, recovery
- **Documentation**: Tutorials, examples, architecture docs
- **Testing**: More edge cases, integration tests

### Medium Priority
- **Additional compression**: zstd, lzma support
- **Output formats**: SVG, PNG sheets
- **Mobile app**: Scanning QR codes on phone
- **GUI**: Desktop application for non-technical users

### Nice to Have
- **Internationalization**: Multi-language support
- **Cloud integration**: Optional encrypted cloud backup
- **Advanced features**: Shamir's Secret Sharing for password splitting
- **Analysis tools**: Estimate pages needed before encoding

## Questions?

- **General questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security issues**: See SECURITY.md
- **Private inquiries**: Email maintainers (see README)

---

**Thank you for contributing! 🎉**

Every contribution, no matter how small, makes this project better.
