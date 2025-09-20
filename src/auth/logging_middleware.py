"""Logging middleware for Flask."""
import time
from datetime import datetime
from typing import Callable, Dict, Any

from flask import Flask, request, g


class RequestLogger:
    """Middleware to log request information."""
    
    def __init__(self, app: Flask = None):
        """Initialize the logger."""
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Register the middleware with a Flask app."""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
    
    def before_request(self) -> None:
        """Before request handler."""
        g.start_time = time.time()
        g.request_id = int(time.time() * 1000)  # Simple request ID based on timestamp
        
        # Log the request
        self._log_request()
    
    def after_request(self, response: Any) -> Any:
        """After request handler."""
        # Calculate request duration
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            # Log the response
            self._log_response(response, duration)
        
        return response
    
    def _log_request(self) -> None:
        """Log the request details."""
        timestamp = datetime.utcnow().isoformat()
        user_id = getattr(g, 'user', {}).get('id', 'anonymous')
        user_role = getattr(g, 'user', {}).get('role', 'anonymous')
        
        log_data = {
            'timestamp': timestamp,
            'request_id': g.request_id,
            'method': request.method,
            'path': request.path,
            'remote_addr': request.remote_addr,
            'user_id': user_id,
            'user_role': user_role,
            'headers': dict(request.headers),
        }
        
        # Add query parameters if present
        if request.args:
            log_data['query_params'] = dict(request.args)
        
        # Add request body for appropriate methods, excluding sensitive data
        if request.method in ['POST', 'PUT', 'PATCH'] and request.is_json:
            body = request.get_json(silent=True) or {}
            # Filter out sensitive fields
            if isinstance(body, dict):
                filtered_body = body.copy()
                for sensitive_field in ['password', 'token', 'api_key', 'secret']:
                    if sensitive_field in filtered_body:
                        filtered_body[sensitive_field] = '[FILTERED]'
                log_data['body'] = filtered_body
        
        # In a real-world application, use a proper logging system
        print(f"[REQUEST] {log_data}")
    
    def _log_response(self, response: Any, duration: float) -> None:
        """Log the response details."""
        timestamp = datetime.utcnow().isoformat()
        
        log_data = {
            'timestamp': timestamp,
            'request_id': getattr(g, 'request_id', 'unknown'),
            'status_code': response.status_code,
            'duration_ms': round(duration * 1000, 2),
            'content_length': response.content_length,
            'content_type': response.content_type,
        }
        
        # In a real-world application, use a proper logging system
        print(f"[RESPONSE] {log_data}")