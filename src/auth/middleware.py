"""Authentication and authorization middleware."""
from functools import wraps
from typing import Callable, Dict, Optional

import jwt
from flask import request, jsonify, g

from src.auth.models import UserStore
from src.core.config import get_settings


settings = get_settings()
user_store = UserStore()


def get_token_from_request() -> Optional[str]:
    """Extract token from request headers."""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None
    
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    
    return parts[1]


def decode_token(token: str) -> Optional[Dict]:
    """Decode and verify JWT token."""
    try:
        payload = jwt.decode(
            token, 
            settings.jwt_secret_key, 
            algorithms=[settings.jwt_algorithm]
        )
        return payload
    except jwt.ExpiredSignatureError:
        # Token has expired
        return None
    except jwt.InvalidTokenError:
        # Invalid token
        return None


def authenticate() -> Optional[Dict]:
    """Authenticate request based on token."""
    token = get_token_from_request()
    if not token:
        return None
    
    payload = decode_token(token)
    if not payload:
        return None
    
    user_id = payload.get('sub')
    if not user_id:
        return None
    
    # Get user from store
    user = user_store.get_by_id(user_id)
    if not user:
        return None
    
    return {
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'user': user
    }


def login_required(f: Callable) -> Callable:
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_data = authenticate()
        if not auth_data:
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please provide valid authentication token'
            }), 401
        
        # Store user information in Flask's g object for the request
        g.user_id = auth_data['user_id']
        g.username = auth_data['username']
        g.role = auth_data['role']
        g.user = auth_data['user']
        
        return f(*args, **kwargs)
    
    return decorated


def role_required(roles: list) -> Callable:
    """Decorator to require specific role(s)."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            if g.role not in roles:
                return jsonify({
                    'error': 'Permission denied',
                    'message': f'Required role: {", ".join(roles)}'
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated
    
    return decorator