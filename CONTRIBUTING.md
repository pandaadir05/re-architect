# Contributing to RE-Architect

Thank you for your interest in contributing to RE-Architect! This document provides guidelines and instructions for contributing to this project.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Coding Standards](#coding-standards)
- [Pull Request Process](#pull-request-process)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)

## Code of Conduct

By participating in this project, you are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/re-architect.git
   cd re-architect
   ```
3. Set up your development environment (see [Development Environment](#development-environment))
4. Create a branch for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Environment

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

2. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

3. Set up pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Coding Standards

We follow these coding standards:

- Code formatting with Black (line length of 100 characters)
- Type hints for all function arguments and return values
- Docstrings for all public classes and methods (Google style)
- Code linting with Flake8
- Import sorting with isort

Run the linting tools:
```bash
make lint
```

## Pull Request Process

1. Ensure your code follows our coding standards
2. Add or update tests as necessary
3. Update documentation as needed
4. Make sure all tests pass:
   ```bash
   make test
   ```
5. Submit a pull request to the `develop` branch
6. Include a clear description of the changes and any relevant issue numbers
7. Wait for review and address any feedback

## Testing Guidelines

- Write tests for all new functionality
- Ensure existing tests pass
- Use pytest for testing
- Target at least 80% code coverage

Run the tests:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=src tests/
```

## Documentation

- Update documentation for any changed functionality
- Add docstrings to all public classes, methods, and functions
- Keep the README up to date
- Add examples for new features

## Branch Structure

- `main`: Production-ready code
- `develop`: Active development branch
- Feature branches: `feature/feature-name`
- Bug fix branches: `fix/bug-description`

Thank you for contributing to RE-Architect!
