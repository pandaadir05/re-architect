"""
Advanced error handling and monitoring for RE-Architect.

This module provides enterprise-grade error handling, structured logging,
and monitoring capabilities for the RE-Architect application.
"""

import logging
import traceback
import functools
import time
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import uuid

# Performance monitoring
import psutil


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high" 
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error category types."""
    SECURITY = "security"
    PERFORMANCE = "performance"
    RESOURCE = "resource"
    VALIDATION = "validation"
    NETWORK = "network"
    FILE_SYSTEM = "file_system"
    DECOMPILER = "decompiler"
    ANALYSIS = "analysis"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


@dataclass
class ErrorReport:
    """Structured error report."""
    error_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    category: ErrorCategory = ErrorCategory.UNKNOWN
    component: str = ""
    message: str = ""
    exception_type: Optional[str] = None
    stack_trace: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    user_action: Optional[str] = None
    resolution_steps: List[str] = field(default_factory=list)
    performance_impact: Optional[Dict[str, float]] = None


class PerformanceMonitor:
    """System performance monitoring."""
    
    def __init__(self):
        self.start_time = time.time()
        self.metrics = {}
        self._lock = threading.Lock()
    
    def start_operation(self, operation_name: str) -> str:
        """Start monitoring an operation."""
        operation_id = str(uuid.uuid4())
        
        with self._lock:
            self.metrics[operation_id] = {
                'name': operation_name,
                'start_time': time.time(),
                'start_memory': self.get_memory_usage(),
                'start_cpu': psutil.cpu_percent(),
            }
        
        return operation_id
    
    def end_operation(self, operation_id: str) -> Dict[str, float]:
        """End monitoring an operation and return metrics."""
        end_time = time.time()
        end_memory = self.get_memory_usage()
        end_cpu = psutil.cpu_percent()
        
        with self._lock:
            if operation_id not in self.metrics:
                return {}
            
            start_metrics = self.metrics[operation_id]
            
            performance_data = {
                'duration': end_time - start_metrics['start_time'],
                'memory_delta': end_memory - start_metrics['start_memory'],
                'avg_cpu': (start_metrics['start_cpu'] + end_cpu) / 2,
                'peak_memory': end_memory,
            }
            
            # Clean up
            del self.metrics[operation_id]
            
        return performance_data
    
    @staticmethod
    def get_memory_usage() -> float:
        """Get current memory usage in MB."""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    @staticmethod
    def get_system_metrics() -> Dict[str, float]:
        """Get system-wide metrics."""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'load_average': psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0.0,
        }


class StructuredLogger:
    """Structured logging with JSON output and context management."""
    
    def __init__(self, name: str, log_level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        
        # Configure JSON formatter
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = self.JSONFormatter()
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        self.context = threading.local()
        self.performance_monitor = PerformanceMonitor()
    
    def set_context(self, **context):
        """Set logging context for current thread."""
        if not hasattr(self.context, 'data'):
            self.context.data = {}
        self.context.data.update(context)
    
    def clear_context(self):
        """Clear logging context."""
        if hasattr(self.context, 'data'):
            self.context.data.clear()
    
    def _get_context(self) -> Dict[str, Any]:
        """Get current logging context."""
        if hasattr(self.context, 'data'):
            return self.context.data.copy()
        return {}
    
    def log_structured(self, level: int, message: str, **extra):
        """Log a structured message with context."""
        context = self._get_context()
        context.update(extra)
        
        # Add system metrics for important events
        if level >= logging.WARNING:
            context['system_metrics'] = self.performance_monitor.get_system_metrics()
        
        self.logger.log(level, message, extra=context)
    
    def info(self, message: str, **extra):
        """Log info message."""
        self.log_structured(logging.INFO, message, **extra)
    
    def warning(self, message: str, **extra):
        """Log warning message."""
        self.log_structured(logging.WARNING, message, **extra)
    
    def error(self, message: str, **extra):
        """Log error message."""
        self.log_structured(logging.ERROR, message, **extra)
    
    def critical(self, message: str, **extra):
        """Log critical message."""
        self.log_structured(logging.CRITICAL, message, **extra)
    
    class JSONFormatter(logging.Formatter):
        """JSON formatter for structured logging."""
        
        def format(self, record):
            log_obj = {
                'timestamp': datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno,
            }
            
            # Add extra context
            if hasattr(record, 'extra'):
                log_obj.update(record.extra)
            
            # Add exception info if present
            if record.exc_info:
                log_obj['exception'] = {
                    'type': record.exc_info[0].__name__,
                    'message': str(record.exc_info[1]),
                    'traceback': traceback.format_exception(*record.exc_info),
                }
            
            return json.dumps(log_obj)


class ErrorHandler:
    """Advanced error handling and reporting."""
    
    def __init__(self, logger: Optional[StructuredLogger] = None):
        self.logger = logger or StructuredLogger("re-architect.errors")
        self.error_reports: List[ErrorReport] = []
        self.error_callbacks: List[Callable[[ErrorReport], None]] = []
        self._lock = threading.Lock()
    
    def add_error_callback(self, callback: Callable[[ErrorReport], None]):
        """Add callback for error notifications."""
        self.error_callbacks.append(callback)
    
    def handle_error(self, 
                    exception: Exception,
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    category: ErrorCategory = ErrorCategory.UNKNOWN,
                    component: str = "",
                    context: Optional[Dict[str, Any]] = None,
                    user_action: Optional[str] = None,
                    resolution_steps: Optional[List[str]] = None) -> ErrorReport:
        """
        Handle an error with comprehensive reporting.
        
        Args:
            exception: The exception that occurred
            severity: Error severity level
            category: Error category
            component: Component where error occurred
            context: Additional context information
            user_action: User action that triggered the error
            resolution_steps: Suggested resolution steps
            
        Returns:
            ErrorReport object
        """
        # Create error report
        report = ErrorReport(
            severity=severity,
            category=category,
            component=component,
            message=str(exception),
            exception_type=type(exception).__name__,
            stack_trace=traceback.format_exc(),
            context=context or {},
            user_action=user_action,
            resolution_steps=resolution_steps or []
        )
        
        # Add performance impact if it's a performance-related error
        if category == ErrorCategory.PERFORMANCE:
            report.performance_impact = PerformanceMonitor.get_system_metrics()
        
        # Store report
        with self._lock:
            self.error_reports.append(report)
        
        # Log the error
        self.logger.error(
            f"Error in {component}: {exception}",
            error_id=report.error_id,
            severity=severity.value,
            category=category.value,
            exception_type=report.exception_type,
            context=report.context
        )
        
        # Notify callbacks
        for callback in self.error_callbacks:
            try:
                callback(report)
            except Exception as e:
                self.logger.warning(f"Error callback failed: {e}")
        
        return report
    
    def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get error summary for the last N hours."""
        cutoff_time = datetime.now(timezone.utc).timestamp() - (hours * 3600)
        
        recent_errors = [
            report for report in self.error_reports
            if report.timestamp.timestamp() > cutoff_time
        ]
        
        # Group by category and severity
        by_category = {}
        by_severity = {}
        
        for report in recent_errors:
            category = report.category.value
            severity = report.severity.value
            
            by_category[category] = by_category.get(category, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            'total_errors': len(recent_errors),
            'by_category': by_category,
            'by_severity': by_severity,
            'time_window_hours': hours,
        }
    
    def export_error_reports(self, output_path: Union[str, Path]) -> None:
        """Export error reports to JSON file."""
        output_path = Path(output_path)
        
        reports_data = []
        for report in self.error_reports:
            reports_data.append({
                'error_id': report.error_id,
                'timestamp': report.timestamp.isoformat(),
                'severity': report.severity.value,
                'category': report.category.value,
                'component': report.component,
                'message': report.message,
                'exception_type': report.exception_type,
                'context': report.context,
                'user_action': report.user_action,
                'resolution_steps': report.resolution_steps,
                'performance_impact': report.performance_impact,
            })
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(reports_data, f, indent=2, default=str)
        
        self.logger.info(f"Exported {len(reports_data)} error reports to {output_path}")


def monitored_operation(component: str = "", 
                       category: ErrorCategory = ErrorCategory.UNKNOWN,
                       severity: ErrorSeverity = ErrorSeverity.MEDIUM):
    """
    Decorator for monitoring operations with automatic error handling.
    
    Args:
        component: Component name for error reporting
        category: Error category
        severity: Error severity level
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get or create error handler
            error_handler = getattr(wrapper, '_error_handler', None)
            if error_handler is None:
                error_handler = ErrorHandler()
                wrapper._error_handler = error_handler
            
            # Start performance monitoring
            perf_monitor = PerformanceMonitor()
            op_id = perf_monitor.start_operation(func.__name__)
            
            try:
                # Set logging context
                logger = StructuredLogger(f"re-architect.{component}")
                logger.set_context(
                    operation=func.__name__,
                    component=component,
                    operation_id=op_id
                )
                
                logger.info(f"Starting operation: {func.__name__}")
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Log success
                performance_data = perf_monitor.end_operation(op_id)
                logger.info(
                    f"Operation completed: {func.__name__}",
                    performance=performance_data
                )
                
                return result
                
            except Exception as e:
                # Get performance impact
                performance_data = perf_monitor.end_operation(op_id)
                
                # Handle error
                error_handler.handle_error(
                    exception=e,
                    severity=severity,
                    category=category,
                    component=component,
                    context={
                        'function': func.__name__,
                        'args_count': len(args),
                        'kwargs_keys': list(kwargs.keys()),
                        'performance_impact': performance_data,
                    }
                )
                
                # Re-raise the exception
                raise
            
            finally:
                # Clear logging context
                if 'logger' in locals():
                    logger.clear_context()
        
        return wrapper
    return decorator


def setup_global_error_handling(log_file: Optional[Union[str, Path]] = None):
    """
    Set up global error handling for the application.
    
    Args:
        log_file: Optional log file path
    """
    # Create global error handler
    global_logger = StructuredLogger("re-architect.global")
    global_error_handler = ErrorHandler(global_logger)
    
    # Set up file logging if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(global_logger.JSONFormatter())
        global_logger.logger.addHandler(file_handler)
    
    # Handle uncaught exceptions
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        global_error_handler.handle_error(
            exception=exc_value,
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.UNKNOWN,
            component="global",
            context={
                'uncaught_exception': True,
                'exception_type': exc_type.__name__,
            }
        )
    
    sys.excepthook = handle_exception
    
    return global_error_handler