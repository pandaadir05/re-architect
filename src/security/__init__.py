"""
Security utilities for RE-Architect.

This module provides security-focused utilities for safe file operations,
input validation, and subprocess execution to prevent common security
vulnerabilities.
"""

__all__ = [
    'SecurityValidator',
    'SecurityAudit', 
    'SecurityError',
    'PathTraversalError',
    'InputValidationError',
    'UnsafeOperationError'
]

import os
import re
import shlex
import subprocess
import logging
from pathlib import Path, PurePath
from typing import List, Dict, Any, Optional, Union
import hashlib
import tempfile

logger = logging.getLogger("re-architect.security")

class SecurityError(Exception):
    """Raised when a security validation fails."""
    pass

class PathTraversalError(SecurityError):
    """Raised when path traversal is detected."""
    pass

class InputValidationError(SecurityError):
    """Raised when input validation fails."""
    pass

class UnsafeOperationError(SecurityError):
    """Raised when an unsafe operation is attempted."""
    pass

class SecurityValidator:
    """
    Security validator for RE-Architect operations.
    
    Provides methods to validate inputs, sanitize paths, and ensure
    safe operations throughout the application.
    """
    
    # Allowed file extensions for analysis
    ALLOWED_BINARY_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib', '.bin', '.elf', 
        '.o', '.obj', '.a', '.lib', '.sys', '.ko'
    }
    
    # Dangerous characters in filenames
    DANGEROUS_FILENAME_CHARS = ['..', '~', '$', '`', '|', '&', ';', '<', '>', '(', ')', '[', ']', '{', '}', '"', "'", '\\']
    
    # Maximum file size for analysis (500MB)
    MAX_FILE_SIZE = 500 * 1024 * 1024
    
    # Safe characters for identifiers
    SAFE_IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
    
    @staticmethod
    def validate_file_path(file_path: Union[str, Path], base_dir: Optional[Union[str, Path]] = None) -> Path:
        """
        Validate and sanitize a file path to prevent path traversal attacks.
        
        Args:
            file_path: Path to validate
            base_dir: Optional base directory to restrict path to
            
        Returns:
            Validated Path object
            
        Raises:
            PathTraversalError: If path traversal is detected
            FileNotFoundError: If file doesn't exist
            SecurityError: If path is unsafe
        """
        try:
            # Convert to Path object
            path = Path(file_path).resolve()
            
            # Check for dangerous patterns
            path_str = str(path)
            for dangerous_char in SecurityValidator.DANGEROUS_FILENAME_CHARS:
                if dangerous_char in path_str:
                    raise PathTraversalError(f"Dangerous character '{dangerous_char}' in path: {path}")
            
            # If base_dir is provided, ensure path is within it
            if base_dir:
                base_path = Path(base_dir).resolve()
                try:
                    path.relative_to(base_path)
                except ValueError:
                    raise PathTraversalError(f"Path {path} is outside base directory {base_path}")
            
            # Check if file exists
            if not path.exists():
                raise FileNotFoundError(f"File not found: {path}")
            
            # Check if it's actually a file (not a directory or special file)
            if not path.is_file():
                raise SecurityError(f"Path is not a regular file: {path}")
            
            return path
            
        except Exception as e:
            if isinstance(e, (PathTraversalError, FileNotFoundError, SecurityError)):
                raise
            raise SecurityError(f"Invalid path: {file_path}") from e
    
    @staticmethod
    def validate_binary_file(file_path: Union[str, Path], check_size: bool = True) -> Path:
        """
        Validate a binary file for analysis.
        
        Args:
            file_path: Path to binary file
            check_size: Whether to check file size limits
            
        Returns:
            Validated Path object
            
        Raises:
            SecurityError: If file is unsafe for analysis
        """
        path = SecurityValidator.validate_file_path(file_path)
        
        # Check file extension
        if path.suffix.lower() not in SecurityValidator.ALLOWED_BINARY_EXTENSIONS:
            logger.warning(f"File has unexpected extension: {path.suffix}")
            # Don't raise an error, but log the warning
        
        # Check file size
        if check_size:
            file_size = path.stat().st_size
            if file_size > SecurityValidator.MAX_FILE_SIZE:
                raise SecurityError(
                    f"File too large: {file_size} bytes (max: {SecurityValidator.MAX_FILE_SIZE})"
                )
            
            if file_size == 0:
                raise SecurityError("File is empty")
        
        return path
    
    @staticmethod
    def validate_output_directory(dir_path: Union[str, Path], create_if_missing: bool = True) -> Path:
        """
        Validate and create output directory.
        
        Args:
            dir_path: Directory path to validate
            create_if_missing: Whether to create directory if it doesn't exist
            
        Returns:
            Validated Path object
            
        Raises:
            SecurityError: If directory is unsafe
        """
        try:
            path = Path(dir_path).resolve()
            
            # Check for dangerous patterns
            path_str = str(path)
            for dangerous_char in SecurityValidator.DANGEROUS_FILENAME_CHARS:
                if dangerous_char in path_str:
                    raise PathTraversalError(f"Dangerous character '{dangerous_char}' in path: {path}")
            
            if path.exists():
                if not path.is_dir():
                    raise SecurityError(f"Path exists but is not a directory: {path}")
            elif create_if_missing:
                path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created output directory: {path}")
            
            return path
            
        except Exception as e:
            if isinstance(e, (PathTraversalError, SecurityError)):
                raise
            raise SecurityError(f"Invalid directory path: {dir_path}") from e
    
    @staticmethod
    def validate_identifier(identifier: str, max_length: int = 255) -> str:
        """
        Validate an identifier (function name, variable name, etc.).
        
        Args:
            identifier: Identifier to validate
            max_length: Maximum allowed length
            
        Returns:
            Validated identifier
            
        Raises:
            InputValidationError: If identifier is invalid
        """
        if not isinstance(identifier, str):
            raise InputValidationError("Identifier must be a string")
        
        if len(identifier) == 0:
            raise InputValidationError("Identifier cannot be empty")
        
        if len(identifier) > max_length:
            raise InputValidationError(f"Identifier too long: {len(identifier)} > {max_length}")
        
        if not SecurityValidator.SAFE_IDENTIFIER_PATTERN.match(identifier):
            raise InputValidationError(f"Identifier contains unsafe characters: {identifier}")
        
        return identifier
    
    @staticmethod
    def safe_subprocess_run(cmd: List[str], 
                           timeout: Optional[int] = None,
                           cwd: Optional[Union[str, Path]] = None,
                           env: Optional[Dict[str, str]] = None,
                           **kwargs) -> subprocess.CompletedProcess:
        """
        Safely execute a subprocess command with security controls.
        
        Args:
            cmd: Command and arguments as a list
            timeout: Timeout in seconds
            cwd: Working directory
            env: Environment variables
            **kwargs: Additional subprocess arguments
            
        Returns:
            CompletedProcess result
            
        Raises:
            UnsafeOperationError: If command is unsafe
            subprocess.SubprocessError: If execution fails
        """
        if not isinstance(cmd, list):
            raise UnsafeOperationError("Command must be a list, not a string")
        
        if not cmd:
            raise UnsafeOperationError("Command list cannot be empty")
        
        # Validate executable path
        executable = Path(cmd[0])
        if not executable.is_absolute():
            # Try to find the executable in PATH
            executable = SecurityValidator._find_executable(cmd[0])
            if not executable:
                raise UnsafeOperationError(f"Executable not found: {cmd[0]}")
        
        # Validate working directory
        if cwd:
            cwd_path = SecurityValidator.validate_output_directory(cwd, create_if_missing=False)
            cwd = str(cwd_path)
        
        # Sanitize environment variables
        if env:
            env = SecurityValidator._sanitize_env(env)
        
        # Set safe defaults
        safe_kwargs = {
            'stdout': subprocess.PIPE,
            'stderr': subprocess.PIPE,
            'text': True,
            'timeout': timeout or 300,  # Default 5-minute timeout
            'check': False,  # Don't raise exception on non-zero exit
        }
        safe_kwargs.update(kwargs)
        
        # Log the command (but sanitize sensitive data)
        safe_cmd_log = SecurityValidator._sanitize_command_for_logging(cmd)
        logger.info(f"Executing command: {' '.join(safe_cmd_log)}")
        
        try:
            return subprocess.run(cmd, cwd=cwd, env=env, **safe_kwargs)
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timed out after {timeout} seconds: {cmd[0]}")
            raise
        except Exception as e:
            logger.error(f"Command execution failed: {cmd[0]} - {e}")
            raise
    
    @staticmethod
    def _find_executable(name: str) -> Optional[Path]:
        """Find executable in PATH."""
        import shutil
        exec_path = shutil.which(name)
        return Path(exec_path) if exec_path else None
    
    @staticmethod
    def _sanitize_env(env: Dict[str, str]) -> Dict[str, str]:
        """Sanitize environment variables."""
        sanitized = {}
        for key, value in env.items():
            # Only allow safe environment variables
            if key.startswith(('PATH', 'HOME', 'USER', 'TEMP', 'TMP')):
                sanitized[key] = value
        return sanitized
    
    @staticmethod
    def _sanitize_command_for_logging(cmd: List[str]) -> List[str]:
        """Sanitize command for safe logging (remove sensitive data)."""
        sanitized = []
        for arg in cmd:
            # Hide potential passwords, keys, tokens
            if any(sensitive in arg.lower() for sensitive in ['password', 'key', 'token', 'secret']):
                sanitized.append('[REDACTED]')
            else:
                sanitized.append(arg)
        return sanitized
    
    @staticmethod
    def calculate_file_hash(file_path: Union[str, Path], algorithm: str = 'sha256') -> str:
        """
        Calculate cryptographic hash of a file.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm ('md5', 'sha1', 'sha256', 'sha512')
            
        Returns:
            Hexadecimal hash string
        """
        path = SecurityValidator.validate_file_path(file_path)
        
        hasher = hashlib.new(algorithm)
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    @staticmethod
    def create_secure_temp_file(suffix: str = '', prefix: str = 're_architect_') -> Path:
        """
        Create a secure temporary file.
        
        Args:
            suffix: File suffix
            prefix: File prefix
            
        Returns:
            Path to temporary file
        """
        fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
        os.close(fd)
        return Path(temp_path)
    
    @staticmethod
    def create_secure_temp_dir(prefix: str = 're_architect_') -> Path:
        """
        Create a secure temporary directory.
        
        Args:
            prefix: Directory prefix
            
        Returns:
            Path to temporary directory
        """
        temp_dir = tempfile.mkdtemp(prefix=prefix)
        return Path(temp_dir)


class SecurityAudit:
    """Security audit utilities for RE-Architect."""
    
    @staticmethod
    def audit_file_permissions(file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Audit file permissions and ownership.
        
        Args:
            file_path: Path to audit
            
        Returns:
            Dictionary with permission information
        """
        path = Path(file_path)
        stat_info = path.stat()
        
        return {
            'path': str(path),
            'mode': oct(stat_info.st_mode),
            'uid': stat_info.st_uid,
            'gid': stat_info.st_gid,
            'size': stat_info.st_size,
            'is_readable': os.access(path, os.R_OK),
            'is_writable': os.access(path, os.W_OK),
            'is_executable': os.access(path, os.X_OK),
        }
    
    @staticmethod
    def scan_for_suspicious_patterns(file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """
        Scan a file for suspicious patterns that might indicate malware.
        
        Args:
            file_path: Path to scan
            
        Returns:
            List of suspicious patterns found
        """
        path = SecurityValidator.validate_file_path(file_path)
        
        # Basic suspicious patterns (this is a simplified implementation)
        suspicious_patterns = [
            (rb'CreateRemoteThread', 'Code injection function'),
            (rb'VirtualAllocEx', 'Memory allocation in other process'),
            (rb'WriteProcessMemory', 'Memory writing in other process'),
            (rb'SetWindowsHookEx', 'Hook installation'),
            (rb'GetProcAddress', 'Dynamic API resolution'),
            (rb'LoadLibrary', 'Dynamic library loading'),
        ]
        
        findings = []
        try:
            with open(path, 'rb') as f:
                content = f.read()
                
                for pattern, description in suspicious_patterns:
                    matches = []
                    start = 0
                    while True:
                        pos = content.find(pattern, start)
                        if pos == -1:
                            break
                        matches.append(pos)
                        start = pos + 1
                    
                    if matches:
                        findings.append({
                            'pattern': pattern.decode('utf-8', errors='ignore'),
                            'description': description,
                            'positions': matches,
                            'count': len(matches)
                        })
        except Exception as e:
            logger.error(f"Error scanning file for suspicious patterns: {e}")
        
        return findings