"""
Setup script for RE-Architect.

This script allows installing RE-Architect as a Python package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="re-architect",
    version="1.0.0",
    author="RE-Architect Team",
    author_email="contact@re-architect.example.com",
    description="Advanced reverse engineering platform with AI-powered analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pandaadir05/re-architect",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology", 
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9", 
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "re-architect=main:main",
        ],
    },
)
