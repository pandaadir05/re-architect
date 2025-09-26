"""
Performance optimization module for RE-Architect.

This module provides memory management, CPU optimization, async/await patterns,
and performance improvements for binary analysis operations.
"""

import asyncio
import concurrent.futures
import functools
import gc
import multiprocessing
import os
import psutil
import threading
import time
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union, AsyncGenerator, Tuple
import mmap
import tempfile
import lru

# For memory profiling
try:
    import tracemalloc
    TRACEMALLOC_AVAILABLE = True
except ImportError:
    TRACEMALLOC_AVAILABLE = False

# For CPU profiling
try:
    import cProfile
    import pstats
    PROFILING_AVAILABLE = True
except ImportError:
    PROFILING_AVAILABLE = False


@dataclass
class PerformanceMetrics:
    """Performance metrics container."""
    execution_time: float
    memory_usage_mb: float
    peak_memory_mb: float
    cpu_usage_percent: float
    cache_hits: int = 0
    cache_misses: int = 0
    disk_io_mb: float = 0.0
    network_io_mb: float = 0.0


class MemoryManager:
    """Advanced memory management for large binary analysis."""
    
    def __init__(self, max_memory_mb: int = 4096):
        self.max_memory_mb = max_memory_mb
        self.memory_pools = {}
        self.object_cache = weakref.WeakKeyDictionary()
        self._lock = threading.Lock()
        
        # Set up memory monitoring
        self.memory_threshold = max_memory_mb * 0.8  # 80% threshold
        
    @contextmanager
    def memory_pool(self, pool_name: str):
        """Context manager for memory pool allocation."""
        pool_start_memory = self.get_current_memory_mb()
        
        try:
            with self._lock:
                self.memory_pools[pool_name] = {
                    'start_memory': pool_start_memory,
                    'objects': []
                }
            
            yield self.memory_pools[pool_name]
            
        finally:
            # Cleanup pool
            with self._lock:
                if pool_name in self.memory_pools:
                    pool = self.memory_pools[pool_name]
                    
                    # Force garbage collection of pool objects
                    for obj in pool.get('objects', []):
                        del obj
                    
                    del self.memory_pools[pool_name]
            
            # Force garbage collection
            gc.collect()
    
    def register_object(self, pool_name: str, obj: Any) -> None:
        """Register an object in a memory pool."""
        with self._lock:
            if pool_name in self.memory_pools:
                self.memory_pools[pool_name]['objects'].append(obj)
    
    @staticmethod
    def get_current_memory_mb() -> float:
        """Get current memory usage in MB."""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    def check_memory_pressure(self) -> bool:
        """Check if memory usage is approaching limits."""
        current_memory = self.get_current_memory_mb()
        return current_memory > self.memory_threshold
    
    def force_cleanup(self) -> float:
        """Force memory cleanup and return freed memory."""
        before_memory = self.get_current_memory_mb()
        
        # Clear all pools
        with self._lock:
            for pool_name, pool in list(self.memory_pools.items()):
                for obj in pool.get('objects', []):
                    del obj
                del self.memory_pools[pool_name]
        
        # Force garbage collection
        gc.collect()
        
        after_memory = self.get_current_memory_mb()
        return before_memory - after_memory


class AsyncFileProcessor:
    """Async file processing for large binaries."""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or min(32, multiprocessing.cpu_count() + 4)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
    
    async def read_file_chunks(self, 
                              file_path: Path, 
                              chunk_size: int = 1024 * 1024) -> AsyncGenerator[bytes, None]:
        """
        Async generator for reading file in chunks.
        
        Args:
            file_path: Path to file
            chunk_size: Size of each chunk in bytes
            
        Yields:
            File chunks as bytes
        """
        def _read_chunk(f, size):
            return f.read(size)
        
        loop = asyncio.get_event_loop()
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = await loop.run_in_executor(
                    self.executor, 
                    _read_chunk, 
                    f, 
                    chunk_size
                )
                if not chunk:
                    break
                yield chunk
    
    async def memory_mapped_analysis(self, 
                                   file_path: Path,
                                   analysis_func: Callable[[mmap.mmap], Any]) -> Any:
        """
        Perform memory-mapped file analysis for large files.
        
        Args:
            file_path: Path to file
            analysis_func: Function to analyze the memory-mapped file
            
        Returns:
            Analysis result
        """
        def _analyze_mmap():
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    return analysis_func(mm)
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, _analyze_mmap)
    
    async def parallel_processing(self, 
                                 items: List[Any],
                                 process_func: Callable[[Any], Any],
                                 max_concurrent: int = None) -> List[Any]:
        """
        Process items in parallel with concurrency control.
        
        Args:
            items: List of items to process
            process_func: Function to process each item
            max_concurrent: Maximum concurrent operations
            
        Returns:
            List of results
        """
        if max_concurrent is None:
            max_concurrent = self.max_workers
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def _process_item(item):
            async with semaphore:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(self.executor, process_func, item)
        
        tasks = [_process_item(item) for item in items]
        return await asyncio.gather(*tasks)


class CacheManager:
    """Advanced caching with LRU eviction and memory management."""
    
    def __init__(self, max_size: int = 1000, max_memory_mb: int = 512):
        self.max_size = max_size
        self.max_memory_mb = max_memory_mb
        self.cache = {}
        self.access_order = []
        self.memory_usage = 0
        self.hits = 0
        self.misses = 0
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache."""
        with self._lock:
            if key in self.cache:
                # Move to end (most recently used)
                self.access_order.remove(key)
                self.access_order.append(key)
                self.hits += 1
                return self.cache[key]['value']
            else:
                self.misses += 1
                return None
    
    def put(self, key: str, value: Any, size_mb: float = 0.0) -> None:
        """Put item in cache with memory tracking."""
        with self._lock:
            # If key already exists, remove old entry
            if key in self.cache:
                old_size = self.cache[key]['size_mb']
                self.memory_usage -= old_size
                self.access_order.remove(key)
            
            # Check if we need to evict items
            self._evict_if_needed(size_mb)
            
            # Add new entry
            self.cache[key] = {
                'value': value,
                'size_mb': size_mb,
                'timestamp': time.time()
            }
            self.access_order.append(key)
            self.memory_usage += size_mb
    
    def _evict_if_needed(self, new_size_mb: float) -> None:
        """Evict items if cache limits are exceeded."""
        # Evict by size limit
        while len(self.cache) >= self.max_size and self.access_order:
            oldest_key = self.access_order[0]
            self._remove_item(oldest_key)
        
        # Evict by memory limit
        while (self.memory_usage + new_size_mb > self.max_memory_mb and 
               self.access_order):
            oldest_key = self.access_order[0]
            self._remove_item(oldest_key)
    
    def _remove_item(self, key: str) -> None:
        """Remove item from cache."""
        if key in self.cache:
            size_mb = self.cache[key]['size_mb']
            self.memory_usage -= size_mb
            del self.cache[key]
            self.access_order.remove(key)
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self.cache.clear()
            self.access_order.clear()
            self.memory_usage = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.hits + self.misses
        hit_rate = self.hits / total_requests if total_requests > 0 else 0.0
        
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'memory_usage_mb': self.memory_usage,
            'max_memory_mb': self.max_memory_mb,
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate,
        }


def performance_monitor(track_memory: bool = True, 
                       track_cpu: bool = True,
                       enable_profiling: bool = False):
    """
    Decorator for performance monitoring.
    
    Args:
        track_memory: Track memory usage
        track_cpu: Track CPU usage  
        enable_profiling: Enable detailed profiling
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Start monitoring
            start_time = time.time()
            start_memory = MemoryManager.get_current_memory_mb() if track_memory else 0
            
            # CPU monitoring
            process = psutil.Process() if track_cpu else None
            cpu_start = process.cpu_percent() if process else 0
            
            # Memory tracing
            if track_memory and TRACEMALLOC_AVAILABLE:
                tracemalloc.start()
            
            # Profiling
            profiler = None
            if enable_profiling and PROFILING_AVAILABLE:
                profiler = cProfile.Profile()
                profiler.enable()
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Calculate metrics
                end_time = time.time()
                execution_time = end_time - start_time
                
                metrics = PerformanceMetrics(
                    execution_time=execution_time,
                    memory_usage_mb=0,
                    peak_memory_mb=0,
                    cpu_usage_percent=0
                )
                
                if track_memory:
                    end_memory = MemoryManager.get_current_memory_mb()
                    metrics.memory_usage_mb = end_memory - start_memory
                    
                    if TRACEMALLOC_AVAILABLE:
                        current, peak = tracemalloc.get_traced_memory()
                        metrics.peak_memory_mb = peak / 1024 / 1024
                        tracemalloc.stop()
                
                if track_cpu and process:
                    cpu_end = process.cpu_percent()
                    metrics.cpu_usage_percent = (cpu_start + cpu_end) / 2
                
                # Store metrics in function
                if not hasattr(func, '_performance_metrics'):
                    func._performance_metrics = []
                func._performance_metrics.append(metrics)
                
                # Save profiling results
                if profiler:
                    profiler.disable()
                    stats = pstats.Stats(profiler)
                    
                    # Create profile directory if it doesn't exist
                    profile_dir = Path("performance_profiles")
                    profile_dir.mkdir(exist_ok=True)
                    
                    profile_file = profile_dir / f"{func.__name__}_{int(time.time())}.prof"
                    stats.dump_stats(str(profile_file))
                
                return result
                
            except Exception as e:
                # Stop profiling on exception
                if profiler:
                    profiler.disable()
                if track_memory and TRACEMALLOC_AVAILABLE:
                    tracemalloc.stop()
                raise
        
        return wrapper
    return decorator


class ResourceManager:
    """System resource management and optimization."""
    
    def __init__(self):
        self.cpu_count = multiprocessing.cpu_count()
        self.memory_gb = psutil.virtual_memory().total / (1024**3)
        self.optimal_workers = min(self.cpu_count * 2, 32)
        
    @contextmanager
    def cpu_affinity(self, cpu_cores: List[int] = None):
        """Set CPU affinity for the current process."""
        if cpu_cores is None:
            cpu_cores = list(range(min(4, self.cpu_count)))  # Use first 4 cores
        
        process = psutil.Process()
        original_affinity = process.cpu_affinity()
        
        try:
            process.cpu_affinity(cpu_cores)
            yield
        finally:
            process.cpu_affinity(original_affinity)
    
    @contextmanager
    def memory_limit(self, limit_mb: int):
        """Set memory limit for the current process."""
        try:
            import resource
            # Set memory limit (soft limit)
            original_limit = resource.getrlimit(resource.RLIMIT_AS)
            new_limit = (limit_mb * 1024 * 1024, original_limit[1])
            resource.setrlimit(resource.RLIMIT_AS, new_limit)
            yield
        except (ImportError, OSError):
            # Resource module not available on Windows
            yield
        finally:
            try:
                resource.setrlimit(resource.RLIMIT_AS, original_limit)
            except (NameError, OSError):
                pass
    
    def optimize_for_binary_analysis(self) -> Dict[str, Any]:
        """
        Optimize system settings for binary analysis.
        
        Returns:
            Dictionary with optimization settings
        """
        settings = {
            'gc_threshold': gc.get_threshold(),
            'gc_disabled': False,
            'thread_count': self.optimal_workers,
            'memory_limit_mb': min(int(self.memory_gb * 1024 * 0.8), 8192),
            'cpu_cores': list(range(min(self.cpu_count, 8))),
        }
        
        # Optimize garbage collection for large objects
        gc.set_threshold(700, 10, 10)
        
        # Set process priority (if possible)
        try:
            process = psutil.Process()
            if hasattr(process, 'nice'):
                process.nice(-5)  # Higher priority
        except (PermissionError, AttributeError):
            pass
        
        return settings
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information."""
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            'cpu_count': self.cpu_count,
            'memory_total_gb': self.memory_gb,
            'memory_available_gb': memory.available / (1024**3),
            'memory_percent_used': memory.percent,
            'disk_total_gb': disk.total / (1024**3),
            'disk_free_gb': disk.free / (1024**3),
            'disk_percent_used': (disk.used / disk.total) * 100,
            'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0],
            'optimal_workers': self.optimal_workers,
        }


# Global instances
_memory_manager = MemoryManager()
_cache_manager = CacheManager()
_resource_manager = ResourceManager()

# Export convenience functions
def get_memory_manager() -> MemoryManager:
    """Get global memory manager instance."""
    return _memory_manager

def get_cache_manager() -> CacheManager:
    """Get global cache manager instance.""" 
    return _cache_manager

def get_resource_manager() -> ResourceManager:
    """Get global resource manager instance."""
    return _resource_manager