# RE-Architect Production Deployment

This directory contains production-ready Docker configurations for deploying the RE-Architect application.

## Files

- `docker-compose.prod.yml`: Production Docker Compose configuration
- `Dockerfile.prod`: Production Dockerfile for the backend service
- `frontend/Dockerfile.prod`: Production Dockerfile for the frontend service
- `frontend/nginx.prod.conf`: Optimized Nginx configuration for production
- `deploy.sh`: Deployment script for production
- `.env.prod.template`: Template for production environment variables

## Requirements

- Docker Engine (20.10.x or newer)
- Docker Compose (2.x or newer)
- 4GB+ RAM
- 10GB+ disk space

## Deployment Instructions

1. Copy the environment template and fill in your values:

```bash
cp .env.prod.template .env.prod
# Edit .env.prod with your values
```

1. Run the deployment script:

```bash
chmod +x deploy.sh
./deploy.sh
```

1. Access the application:

- Frontend: `http://localhost`
- API: `http://localhost/api`

## Configuration Options

### Scaling Services

To scale the analysis service:

```bash
docker-compose -f docker-compose.prod.yml up -d --scale re-architect=3
```

### Environment Variables

Key environment variables:

- `OPENAI_API_KEY`: Your OpenAI API key (required)
- `GHIDRA_PATH`: Path to Ghidra installation
- `LOG_LEVEL`: Logging level (debug, info, warning, error)

## Security Considerations

- All services use health checks for better reliability
- Frontend uses secure headers and CSP
- API has rate limiting
- Non-root users for containers
- Multi-stage builds for smaller attack surface

## Maintenance

### Logs

```bash
docker-compose -f docker-compose.prod.yml logs -f
```

### Updates

```bash
git pull
./deploy.sh
```

## Troubleshooting

If services fail to start:

1. Check logs: `docker-compose -f docker-compose.prod.yml logs`
2. Verify environment variables in `.env.prod`
3. Check available disk space and memory
4. Ensure ports 80 and 5000 are not in use