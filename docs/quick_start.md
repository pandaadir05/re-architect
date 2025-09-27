# RE-Architect Quick Start Guide

Get RE-Architect up and running in minutes with this step-by-step guide.

---

## Installation

### Prerequisites

* Python 3.8 or higher
* Git
* At least 4GB free disk space

### Step 1: Clone the Repository

```bash
git clone https://github.com/pandaadir05/re-architect.git
cd re-architect
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
pip install -e .
```

### Step 3: Configure Decompilers

Choose one or more decompilers and set their paths in `config.yaml`.

* **Ghidra (Recommended, Free)**: [Download here](https://github.com/NationalSecurityAgency/ghidra/releases)
* **IDA Pro (Commercial)**: [Install here](https://hex-rays.com/)
* **Binary Ninja (Commercial)**: [Install here](https://binary.ninja/)

Example `config.yaml`:

```yaml
decompiler:
  default: ghidra
  ghidra:
    path: /path/to/ghidra
    headless: true
  ida:
    path: /path/to/ida
  binary_ninja:
    path: /path/to/binaryninja

analysis:
  static:
    function_analysis_depth: medium
  dynamic:
    enable: false

llm:
  enable: false
  provider: openai
  api_key: your_api_key_here
```

---

## Basic Usage

### Command Line Analysis

```bash
python main.py analyze sample_binary.exe --output ./results
```

### Web Interface

Start the visualization server:

```bash
python -m src.visualization.server
```

Then open [http://localhost:5000](http://localhost:5000) in your browser.

### With LLM Features

```bash
export OPENAI_API_KEY="your_api_key_here"
python main.py sample.exe --generate-tests --serve
```

---

## Python API Usage

```python
from src.core.pipeline import ReversePipeline
from src.core.config import Config

# Load configuration
config = Config.from_file("config.yaml")

# Create pipeline
pipeline = ReversePipeline(config)

# Analyze binary
results = pipeline.analyze("sample.exe")

print(f"Found {len(results['functions'])} functions")
```

---

## Common Options

| Option             | Description           | Example                   |
| ------------------ | --------------------- | ------------------------- |
| `--config`         | Specify config file   | `--config my_config.yaml` |
| `--output`         | Set output directory  | `--output ./analysis`     |
| `--decompiler`     | Choose decompiler     | `--decompiler ghidra`     |
| `--generate-tests` | Create test harnesses | `--generate-tests`        |
| `--no-llm`         | Disable LLM analysis  | `--no-llm`                |
| `--verbose`        | Enable debug output   | `--verbose`               |
| `--serve`          | Start web server      | `--serve`                 |

---

## Example Workflow

```bash
# 1. Analyze with default settings
python main.py malware.exe --verbose

# 2. Review results
ls output/

# 3. Start web interface
python -m src.visualization.server
```

---

## Troubleshooting

**Decompiler not found**
Check `config.yaml` paths. For auto-detection:

```yaml
decompiler:
  ghidra:
    path: null
```

**No module named 'src'**

```bash
pip install -e .
```

**Memory errors**

```bash
python main.py large_binary.exe --no-llm
```

**Permission errors**

```bash
python main.py binary.exe --output ./analysis
```

---

## Next Steps

1. Explore examples in `tests/`
2. Read the [User Manual](user_manual.md)
3. Review the [API Reference](api_reference.md)
4. Enable LLM features for deeper analysis
5. Customize analysis with your own modules

---

Happy reverse engineering!

---
