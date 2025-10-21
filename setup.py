"""
QR Code Backup - Archive digital data as printable QR codes
"""

from setuptools import setup, find_packages
import os

# Read long description from README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements from requirements.txt
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh
                   if line.strip() and not line.startswith("#")]

# Extract version from qr_code_backup.py
version = "2.0.0"

setup(
    name="qr-code-backup",
    version=version,
    author="QR Code Backup Contributors",
    author_email="",
    description="Archive digital data as printable QR codes for long-term offline storage",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/YOUR_USERNAME/qr-code-backup",
    project_urls={
        "Bug Tracker": "https://github.com/YOUR_USERNAME/qr-code-backup/issues",
        "Documentation": "https://github.com/YOUR_USERNAME/qr-code-backup#readme",
        "Source Code": "https://github.com/YOUR_USERNAME/qr-code-backup",
        "Changelog": "https://github.com/YOUR_USERNAME/qr-code-backup/blob/main/CHANGELOG.md",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: End Users/Desktop",
        "Topic :: System :: Archiving :: Backup",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    keywords=[
        "qr-code",
        "backup",
        "archival",
        "offline-storage",
        "paper-backup",
        "encryption",
        "reed-solomon",
        "data-recovery",
        "disaster-recovery",
        "long-term-storage",
    ],
    py_modules=["qr_code_backup"],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "qr-backup=qr_code_backup:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["README.md", "LICENSE", "CHANGELOG.md"],
    },
    zip_safe=False,
)
