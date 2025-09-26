# Quick Start# Quick Start



Get RE-Architect up and running in minutes.## Basic Usage



## InstallationAnalyze a binary:



1. **Clone the repository**\\\ash

   ```bashpython main.py sample.exe

   git clone https://github.com/pandaadir05/re-architect.git\\\

   cd re-architect

   ```## Configuration



2. **Install dependencies**Set decompiler paths in config.yaml:

   ```bash

   pip install -r requirements.txt\\\yaml

   pip install -e .decompilers:

   ```  ghidra:

    path: \

3. **Configure decompilers**/path/to/ghidra\

   \\\

   Edit `config.yaml` to set your decompiler paths:

   ```yaml## Web Interface

   decompilers:

     ghidra:Start the web server:

       path: "/path/to/ghidra"

     ida:\\\ash

       path: "/path/to/ida"python -m src.visualization.server

     binary_ninja:\\\

       path: "/path/to/binaryninja"

   ```Open http://localhost:5000 to view results.


## Basic Usage

### Analyze a Binary

```bash
python main.py binary_file.exe --config config.yaml
```

### With Custom Output Directory

```bash
python main.py binary_file.exe --output ./analysis_results
```

### Specify Decompiler

```bash
python main.py binary_file.exe --decompiler ghidra
```

## Python API

```python
from src.core.pipeline import ReversePipeline
from src.core.config import Config

# Load configuration
config = Config.from_file("config.yaml")
pipeline = ReversePipeline(config)

# Analyze binary
results = pipeline.analyze("binary_file.exe")

# Access results
functions = results["functions"]
print(f"Found {len(functions)} functions")
```

## Web Interface

Start the visualization server:

```bash
python -m src.visualization.server
```

Then open http://localhost:5000 to explore results interactively.

## Next Steps

- Read the [Installation Guide](installation.md) for detailed setup
- Check the [User Manual](user_manual.md) for comprehensive documentation
- Explore the [API Reference](api_reference.md) for programmatic usage