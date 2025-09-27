# RE-Architect User Manual

Welcome to **RE-Architect**, a reverse-engineering and binary-analysis platform that combines multi-decompiler static analysis with optional LLM-powered insights, an interactive web UI, and automated test generation.

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)

   * [Standard](#standard-installation)
   * [Development](#development-setup)
   * [Docker](#docker-installation)
4. [Configuration](#configuration)
5. [Command Line Usage](#command-line-usage)
6. [Python API](#python-api)
7. [Web Interface](#web-interface)
8. [Advanced Features](#advanced-features)
9. [Decompiler Integration](#decompiler-integration)
10. [LLM Integration](#llm-integration)
11. [Understanding Results](#understanding-results)
12. [Troubleshooting](#troubleshooting)
13. [Best Practices](#best-practices)
14. [Performance Optimization](#performance-optimization)
15. [Test Generation](#test-generation)
16. [Integration (CI/CD & IDE)](#integration-cicd--ide)
17. [Support & Contributing](#support--contributing)

---

## Introduction

RE-Architect transforms binaries into:

* **Function summaries** and cross-references
* **Recovered data structures**
* **Automated test harnesses**
* **Comprehensive reports** and an **interactive web UI**

### Key Features

* **Multi-Decompiler Support**: Ghidra (free), IDA Pro, Binary Ninja
* **LLM-Powered Analysis** (optional): Function summaries, naming, patterns
* **Interactive Web Interface**: Search, call graphs, data types, reports
* **Automated Test Generation**: Per-function harnesses
* **Batch & Headless Modes**: For pipelines and CI

---

## Prerequisites

### System Requirements

* **OS**: Windows 10/11, Linux (Ubuntu 18.04+), or macOS 10.15+
* **Python**: 3.8+ (3.11 recommended)
* **Memory**: 8 GB minimum (16 GB recommended for large binaries)
* **Disk**: ≥ 2 GB free

### Optional Dependencies

* **Ghidra** (recommended, free)
* **IDA Pro** (commercial)
* **Binary Ninja** (commercial)
* **Docker** (for containerized runs)

---

## Installation

### Standard Installation

```bash
git clone https://github.com/pandaadir05/re-architect.git
cd re-architect
pip install -r requirements.txt
pip install -e .
```

### Development Setup

```bash
git clone https://github.com/pandaadir05/re-architect.git
cd re-architect
pip install -r requirements-dev.txt
pip install -e .
pytest     # run tests
flake8 src/ tests/
```

### Docker Installation

```bash
docker build -t re-architect .
docker run -p 5000:5000 -v "$PWD:/workspace" re-architect
```

---

## Configuration

RE-Architect uses a YAML config file (`config.yaml`). Minimal example:

```yaml
# Decompiler settings
decompiler:
  default: ghidra           # ghidra | ida | binja | auto
  ghidra:
    path: null              # auto-detect if null
    headless: true
    timeout: 600
  ida:
    path: /opt/ida
    headless: true
    timeout: 600
  binary_ninja:
    path: /opt/binaryninja
    headless: true
    timeout: 600

# Analysis configuration
analysis:
  static:
    function_analysis_depth: medium   # basic | medium | deep
    data_flow_analysis: true
    control_flow_analysis: true
    string_analysis: true
  dynamic:
    enable: false                     # set true to enable
    sandbox_type: container           # container | vm | none
    max_execution_time: 120

# LLM (optional)
llm:
  enable: false
  provider: openai                    # openai | anthropic | azure
  model: gpt-4-turbo
  api_key: your-api-key-here
  max_tokens: 8192
  temperature: 0.2

# Output
output:
  format: json                        # json | html | text
  generate_reports: true
  save_intermediate_results: false
```

### Environment Variables (optional)

* `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` — LLM keys
* `GHIDRA_PATH` — override Ghidra install path

---

## Command Line Usage

Analyze a binary:

```bash
python main.py analyze binary.exe --output ./results --decompiler ghidra
```

Common options:

```
--config PATH       # config file (default: ./config.yaml)
--output PATH       # output directory (default: ./output)
--decompiler TEXT   # ghidra | ida | binja | auto (default: auto)
--generate-tests    # generate per-function test harnesses
--no-llm            # disable LLM features
--format TEXT       # json | html | text
--verbose, -v       # increase logging (repeatable)
--serve             # start web server after analysis
```

Examples:

```bash
# Default analysis (auto decompiler)
python main.py analyze sample.exe --verbose

# Specify output directory
python main.py analyze sample.exe --output ./analysis

# Choose decompiler
python main.py analyze sample.exe --decompiler ghidra

# Generate tests & serve results
python main.py analyze sample.exe --generate-tests --serve
```

---

## Python API

```python
from src.core.pipeline import ReversePipeline
from src.core.config import Config

config = Config.from_file("config.yaml")
pipeline = ReversePipeline(config)

results = pipeline.analyze(
    binary_path="sample.exe",
    output_dir="./analysis_output",
    decompiler="ghidra",
    generate_tests=True
)

functions = results["functions"]
data_structures = results["data_structures"]
print(f"Analyzed {len(functions)} functions, {len(data_structures)} structures")
```

---

## Web Interface

Start server:

```bash
python -m src.visualization.server
# or with host/port
python -m src.visualization.server --host 0.0.0.0 --port 8080
```

Open: `http://localhost:5000`

Features:

* Interactive **Function Browser**
* **Call Graph** visualization
* **Data Structures** explorer
* Source **viewer** with syntax highlighting
* Downloadable **reports**

Serve immediately after analysis:

```bash
python main.py analyze sample.exe --serve
```

---

## Advanced Features

### Multi-Decompiler Comparison

Run multiple decompilers and compare results (conceptual):

```python
decompilers = ["ghidra", "ida", "binja"]
results = {}
for d in decompilers:
    results[d] = pipeline.analyze(binary_path="target.exe", decompiler=d)

# compare_decompiler_results(...) is a hypothetical utility
comparison = compare_decompiler_results(results)
```

### Batch Processing

```bash
for f in binaries/*.exe; do
  echo "Analyzing $f"
  python main.py analyze "$f" --output "./batch/$(basename "$f" .exe)"
done
```

### Custom Analyzers (plugin example)

```python
from src.analysis.base_analyzer import BaseAnalyzer

class CustomSecurityAnalyzer(BaseAnalyzer):
    def analyze(self, decompiled_code):
        vulns = []
        for fn in decompiled_code.functions.values():
            if self.detect_buffer_overflow(fn):
                vulns.append({"type": "buffer_overflow",
                              "function": fn.name, "severity": "high"})
        return {"vulnerabilities": vulns}

pipeline.add_analyzer(CustomSecurityAnalyzer())
```

---

## Decompiler Integration

### Ghidra (recommended)

Install from NSA GitHub and set path (or leave `null` to auto-detect):

```yaml
decompiler:
  ghidra:
    path: /opt/ghidra
    headless: true
    timeout: 600
```

### IDA Pro

```yaml
decompiler:
  ida:
    path: /opt/ida
    headless: true
    timeout: 600
    batch_mode: true
    use_decompiler: true
```

### Binary Ninja

```yaml
decompiler:
  binary_ninja:
    path: /opt/binaryninja
    headless: true
    timeout: 600
```

---

## LLM Integration

Enable and configure:

```yaml
llm:
  enable: true
  provider: openai           # openai | anthropic | azure
  model: gpt-4-turbo
  api_key: ${OPENAI_API_KEY}
  max_tokens: 8192
  temperature: 0.2
```

**Tips**

* Keep token limits reasonable for speed
* Use `--no-llm` for large batch jobs
* Store keys in env vars, not in code

---

## Understanding Results

### Output Structure

```
output/
├── metadata.json          # Analysis summary & stats
├── functions/
│   ├── functions.json     # All functions overview
│   └── *.json             # Per-function details
├── data_structures/
│   ├── structures.json    # All structures overview
│   └── *.json             # Per-structure details
├── test_harnesses/        # Generated tests (if enabled)
│   ├── tests.json
│   └── func_<addr>.c
└── reports/
    ├── summary.html       # Web-viewable report
    └── analysis.md        # Markdown report
```

---

## Troubleshooting

**Decompiler not found**

* Set correct path in `config.yaml`
* Ensure tool is installed & executable
* For Ghidra, try `path: null` for auto-detect

**No module named `src`**

```bash
pip install -e .
```

**LLM API errors**

* Verify `OPENAI_API_KEY` / provider settings
* Check network and API rate limits

**Out of memory / slow**

* Use `function_analysis_depth: basic`
* Disable LLM: `--no-llm`
* Analyze smaller sections or fewer files
* Increase system memory / use SSD

**Permission errors**

* Choose a writable `--output` directory
* Check disk space

Enable debug logs:

```bash
python main.py analyze binary.exe --verbose --verbose
```

---

## Best Practices

**Security**

* Analyze untrusted binaries in VMs/containers
* Disable network access for targets
* Keep API keys out of source control

**Workflow**

1. Start with **basic** static analysis
2. Refine depth/flags iteratively
3. Validate with multiple decompilers
4. Document findings (reports)
5. Version configs and outputs

---

## Performance Optimization

**Config profile (faster runs)**

```yaml
analysis:
  static:
    function_analysis_depth: basic
    data_flow_analysis: false
llm:
  enable: false
decompiler:
  ghidra:
    timeout: 300
```

**Tips**

* Monitor CPU/RAM; prefer SSDs
* Batch by size/complexity
* Cache intermediate results if enabled

---

## Test Generation

Enable via CLI:

```bash
python main.py analyze sample.exe --generate-tests
```

Python API:

```python
results = pipeline.analyze("sample.exe", generate_tests=True)
for name, code in results.get("test_harnesses", {}).items():
    print(f"Test for {name}:\n{code}")
```

Test types: unit, integration, fuzzing templates, performance.

---

## Integration (CI/CD & IDE)

### GitHub Actions (example)

```yaml
name: Binary Analysis
on: [push]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install
        run: |
          pip install -r requirements.txt
          pip install -e .
      - name: Analyze
        run: python main.py analyze test_binary.exe --output reports/
      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: analysis-reports
          path: reports/
```

### VS Code Task

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Analyze Binary",
      "type": "shell",
      "command": "python",
      "args": ["main.py", "analyze", "${input:binaryPath}", "--output", "./analysis"],
      "group": "build",
      "presentation": { "echo": true, "reveal": "always" }
    }
  ],
  "inputs": [
    { "id": "binaryPath", "description": "Path to binary file", "type": "promptString" }
  ]
}
```

---

## Support & Contributing

**Getting Help**

* `docs/` (User Manual, API Reference, Quick Start)
* Examples in `tests/`
* GitHub Issues for bugs & features

**Contributing**

1. Fork the repo
2. Create a feature branch
3. Add tests
4. Open a PR with a clear description

---

**Happy reverse engineering!**

---
