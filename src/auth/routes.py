"""Authentication routes and controllers."""
from datetime import datetime
from typing import Dict, Any, Tuple, Union

from flask import Blueprint, jsonify, request, g
from pydantic import ValidationError, EmailStr

from src.auth.models import User, UserRole, UserStore
from src.auth.middleware import login_required, role_required


# Initialize user store with an admin user
user_store = UserStore()
admin_user = User.create(
    username="admin",
    email="admin@re-architect.local",
    password="admin123",  # This would be a secure password in production
    first_name="Admin",
    last_name="User",
    role=UserRole.ADMIN
)
user_store.add_user(admin_user)

# Create a Blueprint for auth routes
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
def register() -> Tuple[Dict[str, Any], int]:
    """Register a new user."""
    try:
        data = request.get_json()
        
        # Check if username or email already exists
        if user_store.get_by_username(data.get('username')):
            return jsonify({
                'error': 'Username already taken',
                'message': 'Please choose a different username'
            }), 400
        
        if user_store.get_by_email(data.get('email')):
            return jsonify({
                'error': 'Email already registered',
                'message': 'Please use a different email or login to your existing account'
            }), 400
        
        # Create new user
        user = User.create(
            username=data.get('username'),
            email=data.get('email'),
            password=data.get('password'),
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            role=UserRole.ANALYST  # Default role for new users
        )
        
        # Save user to store
        user_store.add_user(user)
        
        # Generate token
        token = user.generate_token()
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': user.to_dict()
        }), 201
        
    except ValidationError as e:
        return jsonify({
            'error': 'Validation error',
            'message': str(e)
        }), 400
    except Exception as e:
        return jsonify({
            'error': 'Registration failed',
            'message': str(e)
        }), 500


@auth_bp.route('/login', methods=['POST'])
def login() -> Tuple[Dict[str, Any], int]:
    """Login user and return token."""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({
                'error': 'Missing credentials',
                'message': 'Username and password are required'
            }), 400
        
        # Get user by username
        user = user_store.get_by_username(username)
        if not user:
            return jsonify({
                'error': 'Authentication failed',
                'message': 'Invalid username or password'
            }), 401
        
        # Verify password
        if not user.verify_password(password):
            return jsonify({
                'error': 'Authentication failed',
                'message': 'Invalid username or password'
            }), 401
        
        # Update last login
        user.last_login = datetime.utcnow()
        user_store.update_user(user)
        
        # Generate token
        token = user.generate_token()
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Login failed',
            'message': str(e)
        }), 500


@auth_bp.route('/me', methods=['GET'])
@login_required
def get_current_user() -> Tuple[Dict[str, Any], int]:
    """Get current authenticated user."""
    try:
        user = g.user
        return jsonify({
            'user': user.to_dict()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to retrieve user information',
            'message': str(e)
        }), 500


@auth_bp.route('/users', methods=['GET'])
@role_required([UserRole.ADMIN])
def list_users() -> Tuple[Dict[str, Any], int]:
    """List all users (admin only)."""
    try:
        users = user_store.list_users()
        return jsonify({
            'users': [user.to_dict() for user in users]
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to retrieve users',
            'message': str(e)
        }), 500


@auth_bp.route('/users/<user_id>', methods=['GET'])
@role_required([UserRole.ADMIN])
def get_user(user_id: str) -> Tuple[Dict[str, Any], int]:
    """Get user by ID (admin only)."""
    try:
        user = user_store.get_by_id(user_id)
        if not user:
            return jsonify({
                'error': 'User not found',
                'message': f'No user with ID {user_id}'
            }), 404
            
        return jsonify({
            'user': user.to_dict()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to retrieve user',
            'message': str(e)
        }), 500


@auth_bp.route('/users/<user_id>', methods=['PUT'])
@role_required([UserRole.ADMIN])
def update_user(user_id: str) -> Tuple[Dict[str, Any], int]:
    """Update user (admin only)."""
    try:
        user = user_store.get_by_id(user_id)
        if not user:
            return jsonify({
                'error': 'User not found',
                'message': f'No user with ID {user_id}'
            }), 404
        
        data = request.get_json()
        
        # Update fields
        if 'username' in data:
            # Check if username is taken by another user
            existing = user_store.get_by_username(data['username'])
            if existing and existing.id != user_id:
                return jsonify({
                    'error': 'Username already taken',
                    'message': 'Please choose a different username'
                }), 400
            user.username = data['username']
            
        if 'email' in data:
            # Check if email is taken by another user
            existing = user_store.get_by_email(data['email'])
            if existing and existing.id != user_id:
                return jsonify({
                    'error': 'Email already registered',
                    'message': 'Please use a different email'
                }), 400
            user.email = data['email']
            
        if 'first_name' in data:
            user.first_name = data['first_name']
            
        if 'last_name' in data:
            user.last_name = data['last_name']
            
        if 'role' in data:
            user.role = data['role']
            
        # Update password if provided
        if 'password' in data:
            password_bytes = data['password'].encode('utf-8')
            import bcrypt
            salt = bcrypt.gensalt()
            user.password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
            
        user.updated_at = datetime.utcnow()
        
        # Save updates
        user_store.update_user(user)
        
        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to update user',
            'message': str(e)
        }), 500


@auth_bp.route('/users/<user_id>', methods=['DELETE'])
@role_required([UserRole.ADMIN])
def delete_user(user_id: str) -> Tuple[Dict[str, Any], int]:
    """Delete user (admin only)."""
    try:
        user = user_store.get_by_id(user_id)
        if not user:
            return jsonify({
                'error': 'User not found',
                'message': f'No user with ID {user_id}'
            }), 404
            
        # Prevent deleting the last admin user
        admins = [u for u in user_store.list_users() if u.role == UserRole.ADMIN]
        if len(admins) == 1 and user.id == admins[0].id:
            return jsonify({
                'error': 'Cannot delete last admin',
                'message': 'System requires at least one admin user'
            }), 400
            
        user_store.delete_user(user_id)
        
        return jsonify({
            'message': 'User deleted successfully'
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to delete user',
            'message': str(e)
        }), 500