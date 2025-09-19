# RE-Architect

[![Build Status](https://github.com/yourusername/re-architect/workflows/RE-Architect%20CI/badge.svg)](https://github.com/yourusername/re-architect/actions)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

RE-Architect is an advanced automated reverse-engineering pipeline that transforms binary files into human-readable function summaries, data structure definitions, and executable test harnesses—all within minutes. Powered by state-of-the-art AI and binary analysis techniques.

![RE-Architect Banner](docs/images/re-architect-banner.png)

## 🚀 Features

- **Binary Analysis**: Decompiles and analyzes binary files using state-of-the-art techniques
- **Function Summarization**: Generates concise, accurate summaries of function behaviors using LLM technology
- **Data Structure Recovery**: Identifies and reconstructs complex data structures from binaries
- **Test Harness Generation**: Creates runnable test harnesses for recovered functions with built-in safety constraints
- **Interactive Visualization**: Presents results through an intuitive user interface with configurable views
- **Multiple Decompiler Support**: Seamlessly integrates with Ghidra, IDA Pro, and Binary Ninja
- **Cross-Platform**: Works on Windows, Linux, and macOS

## 🏗️ Architecture

RE-Architect consists of several integrated components working together to provide a comprehensive reverse engineering solution:

1. **Binary Loader**: Handles various binary formats (ELF, PE, Mach-O) and architectures (x86, ARM, MIPS)
2. **Decompiler Bridge**: Interfaces with leading decompilers using a uniform abstraction layer
3. **Analysis Engine**: Performs static, dynamic, and symbolic analysis to extract program behavior
4. **LLM Interpreter**: Uses AI to generate natural language explanations of code functionality
5. **Test Generator**: Creates safe, executable test harnesses with appropriate input generation
6. **Visualization Layer**: Provides interactive graphical representations of program structure and data flow

## 🔧 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/re-architect.git
cd re-architect

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .

# Run the analysis on a sample binary
python main.py --input samples/example.exe --output results/ --config config.yaml
```

For Docker users:
```bash
# Build and run using Docker
docker-compose build
docker-compose run re-architect --input /app/samples/example.exe --output /app/results/
```

## 🛠️ Technologies

- **Core Analysis**: Python 3.11+ with specialized binary analysis libraries
- **Decompilation**: Integration with Ghidra, IDA Pro, and Binary Ninja
- **AI Components**: OpenAI API and Anthropic Claude for advanced code understanding
- **Symbolic Execution**: Integration with angr framework
- **Dynamic Analysis**: Sandboxed execution environments using Docker and QEMU
- **Visualization**: Flask/React-based web interface with interactive graphs
- **Testing**: pytest for unit and integration testing
- **CI/CD**: GitHub Actions for automated testing and deployment

## 📚 Documentation

- [Installation Guide](docs/installation.md) - Detailed setup instructions for different environments
- [Quick Start Guide](docs/quick_start.md) - Get up and running in minutes
- [Web Interface](docs/web_interface.md) - Using the React-based visualization interface
- [User Manual](docs/user_manual.md) - Complete usage documentation
- [API Reference](docs/api_reference.md) - Programmatic interfaces for integration
- [Contributing](CONTRIBUTING.md) - Guidelines for contributing to RE-Architect

## 📋 Requirements

- Python 3.11+
- 64-bit operating system (Windows, Linux, or macOS)
- 16GB+ RAM recommended for analyzing large binaries
- CUDA-compatible GPU (optional, for accelerated analysis)
- One or more supported decompilers (Ghidra, IDA Pro, or Binary Ninja)

## 🧪 Example

```python
from re_architect import REPipeline

# Initialize the pipeline with configuration
pipeline = REPipeline("config.yaml")

# Analyze a binary
results = pipeline.analyze("path/to/binary")

# Generate function summaries
summaries = results.get_function_summaries()

# Generate test harnesses
tests = results.generate_test_harnesses()

# Export results
results.export("output_directory")
```

## 📊 Performance

RE-Architect typically processes:

| Binary Size | Processing Time | Memory Usage |
|-------------|-----------------|-------------|
| Small (<1MB) | 1-2 minutes | ~2GB |
| Medium (1-10MB) | 5-10 minutes | ~4GB |
| Large (>10MB) | 15+ minutes | 8GB+ |

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started.

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- The Ghidra team at NSA for their open-source decompiler
- The angr symbolic execution framework
- All open-source libraries used in this project
- The binary analysis research community
