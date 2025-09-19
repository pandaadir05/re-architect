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
    version="0.1.0",
    author="RE-Architect Team",
    author_email="contact@re-architect.example.com",
    description="Automated reverse engineering pipeline",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/re-architect",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "re-architect=main:main",
        ],
    },
)
