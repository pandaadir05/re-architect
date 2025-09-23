# Deployment Guide

## Overview

This guide covers deploying RE-Architect in various environments, from development setups to production deployments with high availability and scalability.

## Prerequisites

### System Requirements

**Minimum:**
- Python 3.11+
- 8GB RAM
- 50GB disk space
- 64-bit operating system

**Recommended for Production:**
- Python 3.11+
- 32GB RAM
- 500GB SSD storage
- Multi-core CPU (8+ cores)
- GPU (optional, for ML acceleration)

### Dependencies

**Core Dependencies:**
```bash
# System packages (Ubuntu/Debian)
sudo apt update
sudo apt install -y python3.11 python3.11-dev python3-pip
sudo apt install -y build-essential git curl

# Python packages
pip install -r requirements.txt
```

**Optional Dependencies:**
```bash
# For visualization
pip install flask gunicorn

# For dynamic analysis
sudo apt install -y qemu-system docker.io

# For documentation
pip install -r requirements-dev.txt
```

## Development Deployment

### Local Development

1. **Clone and Setup:**
   ```bash
   git clone https://github.com/pandaadir05/re-architect.git
   cd re-architect
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure Environment:**
   ```bash
   cp config.yaml config.local.yaml
   # Edit config.local.yaml with your settings
   export OPENAI_API_KEY="your-api-key"
   export GHIDRA_INSTALL_DIR="/path/to/ghidra"
   ```

3. **Run Development Server:**
   ```bash
   # Basic analysis
   python main.py sample_binary.exe --config config.local.yaml
   
   # With web interface
   python main.py sample_binary.exe --serve --config config.local.yaml
   ```

### Docker Development

1. **Build Development Image:**
   ```bash
   docker build -t re-architect:dev -f Dockerfile.dev .
   ```

2. **Run Container:**
   ```bash
   docker run -it --rm \
     -v $(pwd):/app \
     -v $(pwd)/binaries:/binaries \
     -v $(pwd)/output:/output \
     -p 5000:5000 \
     -e OPENAI_API_KEY=$OPENAI_API_KEY \
     re-architect:dev
   ```

## Production Deployment

### Single Server Deployment

#### Using systemd

1. **Create Service User:**
   ```bash
   sudo useradd -r -s /bin/false re-architect
   sudo mkdir -p /opt/re-architect
   sudo chown re-architect:re-architect /opt/re-architect
   ```

2. **Install Application:**
   ```bash
   cd /opt/re-architect
   sudo -u re-architect git clone https://github.com/pandaadir05/re-architect.git .
   sudo -u re-architect python -m venv venv
   sudo -u re-architect venv/bin/pip install -r requirements.txt
   ```

3. **Create systemd Service:**
   ```ini
   # /etc/systemd/system/re-architect.service
   [Unit]
   Description=RE-Architect Analysis Service
   After=network.target
   
   [Service]
   Type=notify
   User=re-architect
   Group=re-architect
   WorkingDirectory=/opt/re-architect
   Environment=PATH=/opt/re-architect/venv/bin
   Environment=OPENAI_API_KEY=your-api-key
   ExecStart=/opt/re-architect/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 src.visualization.server:create_app()
   ExecReload=/bin/kill -s HUP $MAINPID
   Restart=always
   RestartSec=10
   
   [Install]
   WantedBy=multi-user.target
   ```

4. **Enable and Start:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable re-architect
   sudo systemctl start re-architect
   sudo systemctl status re-architect
   ```

#### Using Docker

1. **Create Production Dockerfile:**
   ```dockerfile
   FROM python:3.11-slim
   
   # Install system dependencies
   RUN apt-get update && apt-get install -y \
       build-essential \
       git \
       curl \
       && rm -rf /var/lib/apt/lists/*
   
   # Create app user
   RUN useradd -r -s /bin/false re-architect
   
   # Set working directory
   WORKDIR /app
   
   # Copy requirements and install Python dependencies
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   
   # Copy application code
   COPY . .
   RUN chown -R re-architect:re-architect /app
   
   # Switch to app user
   USER re-architect
   
   # Expose port
   EXPOSE 5000
   
   # Health check
   HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
     CMD curl -f http://localhost:5000/health || exit 1
   
   # Start application
   CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "src.visualization.server:create_app()"]
   ```

2. **Build and Run:**
   ```bash
   docker build -t re-architect:prod .
   
   docker run -d \
     --name re-architect-prod \
     --restart unless-stopped \
     -p 5000:5000 \
     -v /opt/re-architect/data:/app/data \
     -v /opt/re-architect/output:/app/output \
     -v /opt/re-architect/config:/app/config \
     -e OPENAI_API_KEY=$OPENAI_API_KEY \
     re-architect:prod
   ```

### Load Balancer Configuration

#### nginx Load Balancer

```nginx
upstream re_architect_backend {
    server 127.0.0.1:5000 weight=1 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:5001 weight=1 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:5002 weight=1 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name re-architect.example.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name re-architect.example.com;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/re-architect.crt;
    ssl_certificate_key /etc/ssl/private/re-architect.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # File upload limits
    client_max_body_size 1G;
    
    location / {
        proxy_pass http://re_architect_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts for long-running analysis
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
    
    # Static files
    location /static {
        alias /opt/re-architect/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://re_architect_backend;
    }
}
```

## Cloud Deployments

### Amazon Web Services (AWS)

#### EC2 Deployment

1. **Launch EC2 Instance:**
   ```bash
   # Use Amazon Linux 2 or Ubuntu 20.04+
   # Instance type: m5.2xlarge or larger
   # Security groups: HTTP (80), HTTPS (443), SSH (22)
   ```

2. **Setup Script:**
   ```bash
   #!/bin/bash
   
   # Update system
   sudo yum update -y  # Amazon Linux
   # sudo apt update && sudo apt upgrade -y  # Ubuntu
   
   # Install dependencies
   sudo yum install -y python3 python3-pip git docker
   # sudo apt install -y python3 python3-pip git docker.io  # Ubuntu
   
   # Clone and setup application
   cd /opt
   sudo git clone https://github.com/pandaadir05/re-architect.git
   cd re-architect
   sudo python3 -m pip install -r requirements.txt
   
   # Start Docker service
   sudo systemctl start docker
   sudo systemctl enable docker
   
   # Build and run application
   sudo docker build -t re-architect .
   sudo docker run -d --name re-architect -p 80:5000 --restart unless-stopped re-architect
   ```

#### ECS Deployment

1. **Task Definition:**
   ```json
   {
     "family": "re-architect-task",
     "networkMode": "awsvpc",
     "requiresCompatibilities": ["FARGATE"],
     "cpu": "2048",
     "memory": "8192",
     "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
     "containerDefinitions": [
       {
         "name": "re-architect",
         "image": "your-account.dkr.ecr.region.amazonaws.com/re-architect:latest",
         "portMappings": [
           {
             "containerPort": 5000,
             "protocol": "tcp"
           }
         ],
         "environment": [
           {
             "name": "OPENAI_API_KEY",
             "value": "your-api-key"
           }
         ],
         "logConfiguration": {
           "logDriver": "awslogs",
           "options": {
             "awslogs-group": "/ecs/re-architect",
             "awslogs-region": "us-west-2",
             "awslogs-stream-prefix": "ecs"
           }
         }
       }
     ]
   }
   ```

#### Lambda Deployment (for API)

```python
import json
from src.core.pipeline import ReversePipeline
from src.core.config import Config

def lambda_handler(event, context):
    """AWS Lambda handler for RE-Architect analysis."""
    
    # Get binary from S3
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    # Download binary
    binary_path = f"/tmp/{key}"
    s3.download_file(bucket, key, binary_path)
    
    # Analyze
    config = Config({
        "decompiler": {"default": "ghidra"},
        "llm": {"enable": True, "provider": "openai"}
    })
    
    pipeline = ReversePipeline(config)
    results = pipeline.analyze(binary_path)
    
    # Upload results to S3
    results_key = f"analysis/{key}.json"
    s3.put_object(
        Bucket=bucket,
        Key=results_key,
        Body=json.dumps(results)
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps({'results_location': results_key})
    }
```

### Google Cloud Platform (GCP)

#### Compute Engine

```bash
# Create instance
gcloud compute instances create re-architect-instance \
  --image-family=ubuntu-2004-lts \
  --image-project=ubuntu-os-cloud \
  --machine-type=n1-standard-8 \
  --boot-disk-size=100GB \
  --scopes=cloud-platform

# Setup application
gcloud compute ssh re-architect-instance --command="
  sudo apt update && 
  sudo apt install -y python3 python3-pip git docker.io &&
  git clone https://github.com/pandaadir05/re-architect.git &&
  cd re-architect &&
  pip3 install -r requirements.txt
"
```

#### Google Kubernetes Engine (GKE)

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: re-architect
spec:
  replicas: 3
  selector:
    matchLabels:
      app: re-architect
  template:
    metadata:
      labels:
        app: re-architect
    spec:
      containers:
      - name: re-architect
        image: gcr.io/your-project/re-architect:latest
        ports:
        - containerPort: 5000
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: openai-secret
              key: api-key
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "8Gi"
            cpu: "4"

---
apiVersion: v1
kind: Service
metadata:
  name: re-architect-service
spec:
  selector:
    app: re-architect
  ports:
  - port: 80
    targetPort: 5000
  type: LoadBalancer
```

### Microsoft Azure

#### Container Instances

```bash
# Create resource group
az group create --name re-architect-rg --location eastus

# Deploy container
az container create \
  --resource-group re-architect-rg \
  --name re-architect-container \
  --image your-registry.azurecr.io/re-architect:latest \
  --cpu 4 \
  --memory 8 \
  --ports 5000 \
  --environment-variables OPENAI_API_KEY=your-key \
  --restart-policy Always
```

## High Availability Setup

### Multi-Node Cluster

#### Docker Swarm

```bash
# Initialize swarm on manager node
docker swarm init --advertise-addr <manager-ip>

# Join worker nodes
docker swarm join --token <token> <manager-ip>:2377

# Deploy stack
cat > docker-compose.prod.yml << EOF
version: '3.8'
services:
  re-architect:
    image: re-architect:prod
    ports:
      - "5000:5000"
    environment:
      - OPENAI_API_KEY=\${OPENAI_API_KEY}
    volumes:
      - data:/app/data
      - output:/app/output
    deploy:
      replicas: 6
      update_config:
        parallelism: 2
        delay: 10s
      restart_policy:
        condition: on-failure
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  data:
    driver: local
  output:
    driver: local
EOF

docker stack deploy -c docker-compose.prod.yml re-architect
```

#### Kubernetes

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: re-architect

---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: re-architect-config
  namespace: re-architect
data:
  config.yaml: |
    decompiler:
      default: ghidra
    analysis:
      static:
        function_analysis_depth: medium
    llm:
      enable: true
      provider: openai

---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: re-architect
  namespace: re-architect
spec:
  replicas: 5
  selector:
    matchLabels:
      app: re-architect
  template:
    metadata:
      labels:
        app: re-architect
    spec:
      containers:
      - name: re-architect
        image: re-architect:prod
        ports:
        - containerPort: 5000
        env:
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: openai-secret
              key: api-key
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
        - name: data
          mountPath: /app/data
        - name: output
          mountPath: /app/output
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: re-architect-config
      - name: data
        persistentVolumeClaim:
          claimName: re-architect-data-pvc
      - name: output
        persistentVolumeClaim:
          claimName: re-architect-output-pvc

---
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: re-architect-service
  namespace: re-architect
spec:
  selector:
    app: re-architect
  ports:
  - port: 80
    targetPort: 5000
  type: LoadBalancer

---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: re-architect-ingress
  namespace: re-architect
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - re-architect.example.com
    secretName: re-architect-tls
  rules:
  - host: re-architect.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: re-architect-service
            port:
              number: 80
```

## Monitoring and Logging

### Prometheus Monitoring

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 're-architect'
    static_configs:
      - targets: ['localhost:5000']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Application Metrics

```python
# Add to src/visualization/server.py
from prometheus_client import Counter, Histogram, generate_latest

# Metrics
REQUEST_COUNT = Counter('re_architect_requests_total', 'Total requests', ['method', 'endpoint'])
REQUEST_DURATION = Histogram('re_architect_request_duration_seconds', 'Request duration')
ANALYSIS_COUNT = Counter('re_architect_analysis_total', 'Total analyses', ['status'])

@app.route('/metrics')
def metrics():
    return generate_latest()
```

### Centralized Logging

#### ELK Stack

```yaml
# docker-compose.logging.yml
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.14.0
    environment:
      - discovery.type=single-node
    ports:
      - "9200:9200"

  kibana:
    image: docker.elastic.co/kibana/kibana:7.14.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200

  logstash:
    image: docker.elastic.co/logstash/logstash:7.14.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - "5000:5000"
```

## Backup and Recovery

### Data Backup Strategy

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backup/re-architect"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR/$DATE

# Backup application data
tar -czf $BACKUP_DIR/$DATE/data.tar.gz /opt/re-architect/data

# Backup analysis results
tar -czf $BACKUP_DIR/$DATE/output.tar.gz /opt/re-architect/output

# Backup configuration
cp /opt/re-architect/config.yaml $BACKUP_DIR/$DATE/

# Upload to S3 (optional)
aws s3 sync $BACKUP_DIR/$DATE s3://re-architect-backups/$DATE

# Clean old backups (keep 30 days)
find $BACKUP_DIR -type d -mtime +30 -exec rm -rf {} \;
```

### Disaster Recovery

```bash
#!/bin/bash
# restore.sh

BACKUP_DATE=$1
BACKUP_DIR="/backup/re-architect"

if [ -z "$BACKUP_DATE" ]; then
    echo "Usage: $0 <backup_date>"
    exit 1
fi

# Stop services
sudo systemctl stop re-architect

# Restore data
cd /opt/re-architect
sudo tar -xzf $BACKUP_DIR/$BACKUP_DATE/data.tar.gz --strip-components=3
sudo tar -xzf $BACKUP_DIR/$BACKUP_DATE/output.tar.gz --strip-components=3

# Restore configuration
sudo cp $BACKUP_DIR/$BACKUP_DATE/config.yaml .

# Fix permissions
sudo chown -R re-architect:re-architect /opt/re-architect

# Start services
sudo systemctl start re-architect
```

## Performance Tuning

### Application Optimization

```yaml
# config.yaml - Production optimizations
performance:
  parallelism: 16  # Match CPU cores
  memory_limit: 24576  # 24GB
  disk_cache: true
  cache_dir: /fast-ssd/cache

analysis:
  static:
    function_analysis_depth: medium  # Balance speed vs accuracy
  llm:
    max_tokens: 4000  # Reduce for faster processing
    cache_dir: /fast-ssd/llm-cache

visualization:
  server:
    workers: 8  # Match CPU cores
    worker_class: sync
    timeout: 300
```

### Database Optimization

For large-scale deployments with persistent storage:

```python
# Use PostgreSQL for result storage
DATABASE_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 're_architect',
    'user': 're_architect',
    'password': 'secure_password',
    'pool_size': 20,
    'max_overflow': 0
}
```

## Security Configuration

### SSL/TLS Configuration

```bash
# Generate self-signed certificate (development)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# For production, use Let's Encrypt
certbot --nginx -d re-architect.example.com
```

### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# iptables
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP
```

### Application Security

```python
# Environment variables for sensitive data
import os

CONFIG = {
    'openai_api_key': os.environ.get('OPENAI_API_KEY'),
    'secret_key': os.environ.get('SECRET_KEY', os.urandom(32)),
    'database_url': os.environ.get('DATABASE_URL'),
}

# Input validation
from werkzeug.utils import secure_filename

def validate_binary_upload(file):
    if not file:
        return False
    
    filename = secure_filename(file.filename)
    if not filename.endswith(('.exe', '.dll', '.so', '.elf')):
        return False
    
    # Check file size (max 100MB)
    if len(file.read()) > 100 * 1024 * 1024:
        return False
    
    file.seek(0)  # Reset file pointer
    return True
```

## Troubleshooting

### Common Issues

**Memory Issues:**
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head

# Increase swap if needed
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

**Disk Space:**
```bash
# Check disk usage
df -h
du -sh /opt/re-architect/*

# Clean old analysis results
find /opt/re-architect/output -type f -mtime +7 -delete
```

**Network Issues:**
```bash
# Check port availability
netstat -tlnp | grep :5000

# Test connectivity
curl -f http://localhost:5000/health
```

### Log Analysis

```bash
# Application logs
journalctl -u re-architect -f

# Docker logs
docker logs -f re-architect-container

# nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

## Maintenance

### Regular Updates

```bash
#!/bin/bash
# update.sh

# Pull latest code
cd /opt/re-architect
sudo -u re-architect git pull origin main

# Update dependencies
sudo -u re-architect venv/bin/pip install -r requirements.txt

# Restart services
sudo systemctl restart re-architect

# Verify deployment
curl -f http://localhost:5000/health
```

### Health Checks

```bash
#!/bin/bash
# health-check.sh

# Check service status
if ! systemctl is-active --quiet re-architect; then
    echo "Service is down, restarting..."
    sudo systemctl restart re-architect
    exit 1
fi

# Check HTTP endpoint
if ! curl -f http://localhost:5000/health > /dev/null 2>&1; then
    echo "Health check failed"
    exit 1
fi

echo "System healthy"
```

## Support

For deployment-specific issues:
- Review logs carefully
- Check resource utilization
- Verify network connectivity
- Consult the troubleshooting section
- File issues on GitHub with deployment details