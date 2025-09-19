.PHONY: setup clean test lint docker-build docker-run install dev help

# Set default shell to bash
SHELL := /bin/bash

# Python settings
PYTHON := python
PIP := pip
PYTEST := pytest
FLAKE8 := flake8

# Docker settings
DOCKER := docker
DOCKER_COMPOSE := docker-compose
DOCKER_IMAGE := re-architect

help:
	@echo "RE-Architect Makefile"
	@echo "===================="
	@echo ""
	@echo "setup         - Install dependencies and development tools"
	@echo "install       - Install package in development mode"
	@echo "test          - Run tests with pytest"
	@echo "lint          - Run linters (flake8)"
	@echo "clean         - Clean build artifacts"
	@echo "docker-build  - Build Docker image"
	@echo "docker-run    - Run RE-Architect in Docker"
	@echo "web           - Start the web visualization server"
	@echo "dev           - Run in development mode"

setup:
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

install:
	$(PIP) install -e .

test:
	$(PYTEST) tests/

lint:
	$(FLAKE8) src/ tests/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

docker-build:
	$(DOCKER) build -t $(DOCKER_IMAGE) .

docker-run:
	$(DOCKER_COMPOSE) run re-architect $(ARGS)

web:
	$(DOCKER_COMPOSE) up web

dev:
	$(PYTHON) main.py $(ARGS)
