# Quick Start

## Basic Usage

Analyze a binary:

\\\ash
python main.py sample.exe
\\\

## Configuration

Set decompiler paths in config.yaml:

\\\yaml
decompilers:
  ghidra:
    path: \
/path/to/ghidra\
\\\

## Web Interface

Start the web server:

\\\ash
python -m src.visualization.server
\\\

Open http://localhost:5000 to view results.
