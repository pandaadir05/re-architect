"""Authentication module initialization."""

# Import for easier access
from src.auth.models import User, UserRole, UserStore
from src.auth.middleware import login_required, role_required
from src.auth.routes import auth_bp