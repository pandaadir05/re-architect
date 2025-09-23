# RE-Architect

[![Build Status](https://github.com/pandaadir05/re-architect/workflows/RE-Architect%20CI/badge.svg)](https://github.com/pandaadir05/re-architect/actions)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

RE-Architect is an advanced automated reverse-engineering platform that transforms binary files into human-readable function summaries, data structure definitions, and executable test harnesses. The system leverages modern binary analysis techniques and machine learning to provide comprehensive analysis results in an efficient timeframe.

## Features

- **Binary Analysis**: Decompiles and analyzes binary files using advanced techniques
- **Function Summarization**: Generates concise, accurate summaries of function behaviors using machine learning
- **Data Structure Recovery**: Identifies and reconstructs complex data structures from binaries
- **Test Harness Generation**: Creates runnable test harnesses for recovered functions with built-in safety constraints
- **Interactive Visualization**: Presents results through an intuitive user interface with configurable views
- **Multiple Decompiler Support**: Seamlessly integrates with Ghidra, IDA Pro, and Binary Ninja
- **Cross-Platform**: Works on Windows, Linux, and macOS

## Architecture

RE-Architect consists of several integrated components working together to provide a comprehensive reverse engineering solution:

1. **Binary Loader**: Handles various binary formats (ELF, PE, Mach-O) and architectures (x86, ARM, MIPS)
2. **Decompiler Bridge**: Interfaces with leading decompilers using a uniform abstraction layer
3. **Analysis Engine**: Performs static, dynamic, and symbolic analysis to extract program behavior
4. **Machine Learning Interpreter**: Generates natural language explanations of code functionality
5. **Test Generator**: Creates safe, executable test harnesses with appropriate input generation
6. **Visualization Layer**: Provides interactive graphical representations of program structure and data flow

## Quick Start

```bash
# Clone the repository
git clone https://github.com/pandaadir05/re-architect.git
cd re-architect

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .

# Run analysis on a binary
python main.py binary_file.exe --config config.yaml
```

## Technologies

- **Core Analysis**: Python 3.11+ with specialized binary analysis libraries
- **Decompilation**: Integration with Ghidra, IDA Pro, and Binary Ninja
- **Machine Learning Components**: Natural language processing for code understanding
- **Symbolic Execution**: Integration with angr framework
- **Dynamic Analysis**: Sandboxed execution environments using Docker and QEMU
- **Visualization**: Flask-based web interface with interactive graphs
- **Testing**: pytest for unit and integration testing
- **CI/CD**: GitHub Actions for automated testing and deployment

## Documentation

- [Installation Guide](docs/installation.md) - Detailed setup instructions for different environments
- [Quick Start Guide](docs/quick_start.md) - Get up and running in minutes
- [Web Interface](docs/web_interface.md) - Using the visualization interface
- [User Manual](docs/user_manual.md) - Complete usage documentation
- [API Reference](docs/api_reference.md) - Programmatic interfaces for integration

## Requirements

- Python 3.11+
- 64-bit operating system (Windows, Linux, or macOS)
- 16GB+ RAM recommended for analyzing large binaries
- CUDA-compatible GPU (optional, for accelerated analysis)
- One or more supported decompilers (Ghidra, IDA Pro, or Binary Ninja)

## Example

```python
from src.core.pipeline import ReversePipeline
from src.core.config import Config

# Initialize the pipeline with configuration
config = Config.from_file("config.yaml")
pipeline = ReversePipeline(config)

# Analyze a binary
results = pipeline.analyze("path/to/binary.exe")

# Access results
functions = results["functions"]
metadata = results["metadata"]
```

## Performance

Performance varies based on binary complexity, analysis depth, and available decompilers. The system supports both lightweight analysis for quick insights and comprehensive deep analysis for detailed reverse engineering work.

## Contributing

Contributions are welcome. Please follow standard GitHub pull request procedures to submit your changes.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Acknowledgements

- The Ghidra team at NSA for their open-source decompiler
- The angr symbolic execution framework
- All open-source libraries used in this project
- The binary analysis research community
