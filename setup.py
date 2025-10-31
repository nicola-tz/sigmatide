#!/usr/bin/env python3
"""
Setup script for Sigma to OpenTide Converter
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="sigma-opentide-converter",
    version="1.0.0",
    author="Detection Engineering Team",
    author_email="detection@company.com",
    description="Convert Sigma detection rules to OpenTide MDR format",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/sigma-opentide-converter",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sigma-opentide=sigma_opentide_converter.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)