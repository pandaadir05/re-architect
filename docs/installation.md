# RE-Architect Installation Guide

This guide provides detailed instructions for setting up RE-Architect on various platforms.

## Prerequisites

RE-Architect requires the following:

- Python 3.11 or higher
- 64-bit operating system (Windows, Linux, or macOS)
- 16GB+ RAM recommended for analyzing large binaries
- CUDA-compatible GPU (optional, for accelerated analysis)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/re-architect.git
cd re-architect
```

### 2. Set Up a Virtual Environment (Recommended)

#### On Windows:
```powershell
python -m venv venv
.\venv\Scripts\activate
```

#### On Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install External Tools

RE-Architect can integrate with external decompilers for enhanced analysis:

#### Ghidra (Recommended)
1. Download Ghidra from [https://ghidra-sre.org/](https://ghidra-sre.org/)
2. Extract the archive to your preferred location
3. Update the `config.yaml` file with the path to your Ghidra installation

#### IDA Pro (Optional)
1. Install IDA Pro
2. Update the `config.yaml` file with the path to your IDA Pro installation

#### Binary Ninja (Optional)
1. Install Binary Ninja
2. Update the `config.yaml` file with the path to your Binary Ninja installation

### 5. Configure API Keys (Optional)

For LLM-based function summarization, you'll need to set up API keys:

1. Obtain an API key from OpenAI (https://platform.openai.com/) or Anthropic
2. Add the key to your `config.yaml` file:
   ```yaml
   llm:
     enable: true
     provider: openai
     model: gpt-4
     api_key: your_api_key_here
   ```

### 6. Verify Installation

Run the following command to verify that RE-Architect is properly installed:

```bash
python -m unittest discover tests
```

## Running RE-Architect

### Basic Usage

```bash
python main.py path/to/binary --output-dir ./output
```

### Advanced Options

```bash
# Use a specific decompiler
python main.py path/to/binary --decompiler ghidra

# Generate test harnesses
python main.py path/to/binary --generate-tests

# Start the visualization server after analysis
python main.py path/to/binary --serve

# Disable LLM-based analysis
python main.py path/to/binary --no-llm
```

## Troubleshooting

### Common Issues

1. **Missing dependencies**: Ensure all requirements are installed with `pip install -r requirements.txt`
2. **Decompiler path not found**: Update your `config.yaml` with the correct path to your decompiler
3. **LLM API errors**: Verify your API key is correct and has sufficient quota

### Getting Help

If you encounter issues not covered here, please:

1. Check the [GitHub Issues](https://github.com/your-username/re-architect/issues)
2. Join our [Discord community](https://discord.gg/your-invitation)
3. Contact support at support@re-architect.example.com
