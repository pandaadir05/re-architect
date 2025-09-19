#!/bin/bash
# Production deployment script for RE-Architect

set -e

# Display banner
echo "=================================================="
echo "RE-Architect Production Deployment"
echo "=================================================="

# Check if environment file exists
if [ ! -f ".env.prod" ]; then
    echo "Error: .env.prod file not found!"
    echo "Please create a .env.prod file with required environment variables."
    exit 1
fi

# Load environment variables
set -a
source .env.prod
set +a

# Check for required tools
echo "Checking required tools..."
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed. Aborting."; exit 1; }

# Check environment variables
echo "Checking environment variables..."
[ -z "$OPENAI_API_KEY" ] && echo "OPENAI_API_KEY is not set in .env.prod!" && exit 1
[ -z "$GHIDRA_PATH" ] && echo "Warning: GHIDRA_PATH is not set. Using default: /opt/ghidra"

# Build and deploy
echo "Building and deploying containers..."
docker-compose -f docker-compose.prod.yml build

echo "Starting services..."
docker-compose -f docker-compose.prod.yml up -d

# Wait for services to be up
echo "Waiting for services to start..."
sleep 10

# Check health status
echo "Checking service health..."
docker-compose -f docker-compose.prod.yml ps

echo "=================================================="
echo "Deployment complete!"
echo "Frontend is available at http://localhost"
echo "API is available at http://localhost/api"
echo "=================================================="

exit 0