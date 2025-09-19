#!/bin/bash
# Development setup script for RE-Architect

set -e

# Display banner
echo "=================================================="
echo "RE-Architect Development Setup"
echo "=================================================="

# Check if environment file exists
if [ ! -f ".env" ]; then
    echo "Warning: .env file not found. Creating from template..."
    cp .env.prod.template .env
    echo "Please edit .env file with your API keys and settings."
fi

# Check for required tools
echo "Checking required tools..."
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed. Aborting."; exit 1; }

# Show options
echo "What would you like to do?"
echo "1. Start development environment"
echo "2. Stop development environment"
echo "3. View logs"
echo "4. Run tests"
echo "5. Execute backend shell"
echo "6. Execute frontend shell"
echo "7. Exit"

read -p "Enter your choice [1-7]: " choice

case $choice in
    1)
        echo "Starting development environment..."
        docker-compose up -d
        echo "Development environment started!"
        echo "- Frontend: http://localhost:3000"
        echo "- API: http://localhost:5000/api"
        ;;
    2)
        echo "Stopping development environment..."
        docker-compose down
        echo "Development environment stopped."
        ;;
    3)
        echo "Showing logs (Ctrl+C to exit)..."
        docker-compose logs -f
        ;;
    4)
        echo "Running tests..."
        docker-compose run --rm re-architect python -m pytest
        ;;
    5)
        echo "Opening backend shell..."
        docker-compose exec re-architect /bin/bash
        ;;
    6)
        echo "Opening frontend shell..."
        docker-compose exec frontend /bin/sh
        ;;
    7)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid option. Exiting..."
        exit 1
        ;;
esac

exit 0