"""User model for authentication and authorization."""
from datetime import datetime
from typing import Dict, List, Optional

import bcrypt
import jwt
from pydantic import BaseModel, Field, EmailStr

from src.core.config import get_settings


settings = get_settings()


class UserRole(str):
    """User role enum."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(BaseModel):
    """User model for authentication and authorization."""
    id: str
    username: str
    email: EmailStr
    password_hash: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: str = UserRole.VIEWER
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    projects: List[str] = []

    @classmethod
    def create(cls, username: str, email: str, password: str, 
               first_name: Optional[str] = None, last_name: Optional[str] = None,
               role: str = UserRole.VIEWER) -> "User":
        """Create a new user with hashed password."""
        # Hash the password
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        
        # Generate a unique ID (in a real app, this would be handled by the database)
        import uuid
        user_id = str(uuid.uuid4())
        
        return cls(
            id=user_id,
            username=username,
            email=email,
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name,
            role=role
        )
    
    def verify_password(self, password: str) -> bool:
        """Verify if the provided password matches the stored hash."""
        password_bytes = password.encode('utf-8')
        stored_hash = self.password_hash.encode('utf-8')
        return bcrypt.checkpw(password_bytes, stored_hash)
    
    def generate_token(self) -> str:
        """Generate a JWT token for this user."""
        payload = {
            "sub": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "exp": datetime.utcnow() + settings.jwt_expiration_delta
        }
        return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    
    def to_dict(self) -> Dict:
        """Convert user to dictionary without sensitive information."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
            "projects": self.projects
        }


# For development/testing, create an in-memory user store
# In a real application, this would be replaced with a database
class UserStore:
    """Simple in-memory user store for development."""
    
    def __init__(self):
        """Initialize empty user store."""
        self.users = {}
        self.username_to_id = {}
        self.email_to_id = {}
    
    def add_user(self, user: User) -> None:
        """Add a user to the store."""
        self.users[user.id] = user
        self.username_to_id[user.username] = user.id
        self.email_to_id[user.email] = user.id
    
    def get_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self.users.get(user_id)
    
    def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        user_id = self.username_to_id.get(username)
        if user_id:
            return self.users.get(user_id)
        return None
    
    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        user_id = self.email_to_id.get(email)
        if user_id:
            return self.users.get(user_id)
        return None
    
    def update_user(self, user: User) -> None:
        """Update a user in the store."""
        if user.id in self.users:
            # Update lookup tables if username or email changed
            old_user = self.users[user.id]
            if old_user.username != user.username:
                self.username_to_id.pop(old_user.username, None)
                self.username_to_id[user.username] = user.id
            if old_user.email != user.email:
                self.email_to_id.pop(old_user.email, None)
                self.email_to_id[user.email] = user.id
            # Update user
            self.users[user.id] = user
    
    def delete_user(self, user_id: str) -> None:
        """Delete a user from the store."""
        if user_id in self.users:
            user = self.users[user_id]
            self.username_to_id.pop(user.username, None)
            self.email_to_id.pop(user.email, None)
            self.users.pop(user_id)
    
    def list_users(self) -> List[User]:
        """List all users."""
        return list(self.users.values())