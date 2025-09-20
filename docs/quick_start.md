# RE-Architect Quick Start Guide

This guide will help you get started with RE-Architect to analyze binary files and generate human-readable function summaries, data structure definitions, and test harnesses.

## Installation

Make sure you have installed RE-Architect following the [Installation Guide](installation.md).

## Basic Usage

### Analyzing a Binary

To analyze a binary file with default settings:

```bash
python main.py path/to/binary
```

This will:
1. Load and analyze the binary
2. Generate function summaries using LLMs
3. Extract data structures
4. Save results to the `./output` directory

### Viewing Results

Results are saved in multiple formats:
- JSON files containing detailed analysis data
- Interactive web interface for visualization and exploration

To start the visualization server:

```bash
python main.py path/to/binary --serve
```

This will launch a web interface at `http://localhost:5000` where you can explore the analysis results.

The web interface provides visualization capabilities for exploring the analysis results.

## Command Line Options

RE-Architect supports the following command line options:

| Option | Description |
|--------|-------------|
| `--output-dir PATH` | Directory to store output files (default: ./output) |
| `--config PATH` | Path to configuration file (default: ./config.yaml) |
| `--decompiler NAME` | Decompiler to use: ghidra, ida, binja, auto (default: auto) |
| `--verbose, -v` | Increase verbosity (can be used multiple times) |
| `--no-llm` | Disable LLM-based analysis |
| `--generate-tests` | Generate test harnesses for identified functions |
| `--serve` | Start the web visualization server after analysis |

## Examples

### Using a Specific Decompiler

```bash
python main.py path/to/binary --decompiler ghidra
```

### Generating Test Harnesses

```bash
python main.py path/to/binary --generate-tests
```

### Analyzing Without LLM Summaries

```bash
python main.py path/to/binary --no-llm
```

### Increasing Verbosity

```bash
python main.py path/to/binary -vv
```

## Working with Results

### Function Summaries

Function summaries are stored in the `output/functions/` directory. Each function has:

- Natural language description of its purpose
- Parameter explanations
- Return value information
- Notes about algorithms and security implications

### Data Structures

Recovered data structures are stored in the `output/data_structures/` directory, containing:

- Field names and types
- Size information
- Source (decompiler or inferred)

### Test Harnesses

Test harnesses are stored in the `output/tests/` directory. Each test includes:

- Source code that can be compiled and run
- Build script
- Documentation on usage

## Next Steps

- Check out the [Advanced Usage Guide](advanced_usage.md) for more features
- Learn about [Customizing Analysis](customization.md)
- See [Integration Examples](integration.md) for using RE-Architect with other tools
