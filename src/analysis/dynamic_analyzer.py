"""
Dynamic analyzer module for RE-Architect.

This module handles dynamic analysis of binary files.
"""

import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.core.config import Config
from src.core.binary_loader import BinaryInfo

logger = logging.getLogger("re-architect.analysis.dynamic")

class DynamicAnalyzer:
    """
    Dynamic analyzer for RE-Architect.
    
    This class handles dynamic analysis of binary files using
    sandboxed execution and tracing.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the dynamic analyzer.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.enabled = config.get("analysis.dynamic.enable", False)
        self.max_execution_time = config.get("analysis.dynamic.max_execution_time", 60)
        self.memory_limit = config.get("analysis.dynamic.memory_limit", 2048)
        self.sandbox_type = config.get("analysis.dynamic.sandbox_type", "container")
    
    def analyze(self, binary_info: BinaryInfo) -> Dict[str, Any]:
        """
        Perform dynamic analysis on a binary file.
        
        Args:
            binary_info: Information about the binary to analyze
            
        Returns:
            Dictionary containing dynamic analysis results
            
        Raises:
            RuntimeError: If dynamic analysis fails or is not enabled
        """
        if not self.enabled:
            logger.info("Dynamic analysis is disabled")
            return {"enabled": False}
        
        logger.info(f"Starting dynamic analysis of {binary_info.path}")
        
        # Initialize results
        results = {
            "enabled": True,
            "functions": {},
            "memory_access": {},
            "syscalls": [],
            "execution_paths": {}
        }
        
        # Choose and initialize the appropriate execution environment
        environment = self._create_execution_environment()
        
        try:
            # Set up the binary for analysis
            environment.setup(binary_info)
            
            # Perform function tracing
            function_results = self._trace_functions(environment, binary_info)
            results["functions"] = function_results
            
            # Collect memory access patterns
            memory_results = self._analyze_memory_access(environment)
            results["memory_access"] = memory_results
            
            # Collect system call information
            syscall_results = self._collect_syscalls(environment, binary_info)
            results["syscalls"] = syscall_results
            
            # Analyze execution paths
            path_results = self._analyze_execution_paths(environment, binary_info)
            results["execution_paths"] = path_results
            
            logger.info("Dynamic analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error during dynamic analysis: {e}")
            results["error"] = str(e)
            
        finally:
            # Clean up
            environment.cleanup()
        
        return results
    
    def _create_execution_environment(self):
        """
        Create an appropriate execution environment based on configuration.
        
        Returns:
            Execution environment instance
        """
        if self.sandbox_type == "container":
            # Use containerized execution (e.g., Docker)
            from src.analysis.execution.container_environment import ContainerEnvironment
            return ContainerEnvironment(
                max_execution_time=self.max_execution_time,
                memory_limit=self.memory_limit
            )
        elif self.sandbox_type == "vm":
            # Use virtual machine execution
            from src.analysis.execution.vm_environment import VMEnvironment
            return VMEnvironment(
                max_execution_time=self.max_execution_time,
                memory_limit=self.memory_limit
            )
        else:
            # Use local execution (less secure)
            from src.analysis.execution.local_environment import LocalEnvironment
            return LocalEnvironment(
                max_execution_time=self.max_execution_time
            )
    
    def _trace_functions(self, environment, binary_info):
        """
        Trace function execution.
        
        Args:
            environment: Execution environment
            binary_info: Information about the binary
            
        Returns:
            Dictionary containing function tracing results
        """
        # Prefer Frida-based tracing if available/configured.
        use_frida = self.config.get("analysis.dynamic.use_frida", True)
        if use_frida:
            try:
                import frida  # type: ignore
                return self._trace_functions_with_frida(binary_info)
            except Exception as e:
                logger.warning(f"Frida tracing unavailable or failed, falling back: {e}")
        
        # Fallback: try environment-provided tracing hooks
        traces: Any = None
        try:
            if hasattr(environment, "trace_functions"):
                traces = environment.trace_functions(binary_info)
            elif hasattr(environment, "run_with_tracing"):
                traces = environment.run_with_tracing(binary_info)
            elif hasattr(environment, "get_function_trace"):
                traces = environment.get_function_trace()
        except Exception as e:
            logger.warning(f"Function tracing failed: {e}")
            traces = None
        
        if traces is None:
            logger.info("Function tracing not available from the execution environment")
            return {"calls": [], "call_counts": {}, "by_function": {}}
        
        return self._normalize_function_traces(traces)

    def _normalize_function_traces(self, traces: Any) -> Dict[str, Any]:
        call_records: List[Dict[str, Any]] = []
        if isinstance(traces, dict) and "calls" in traces and isinstance(traces["calls"], list):
            call_records = traces["calls"]
        elif isinstance(traces, list):
            call_records = traces
        elif isinstance(traces, dict):
            for func, count in traces.items():
                call_records.append({"name": str(func), "count": int(count) if isinstance(count, int) else 1})
        else:
            logger.info("Unrecognized function trace format; returning empty results")
            return {"calls": [], "call_counts": {}, "by_function": {}}
        
        call_counts: Dict[str, int] = {}
        by_function: Dict[str, Dict[str, Any]] = {}
        normalized_calls: List[Dict[str, Any]] = []
        
        for rec in call_records:
            if not isinstance(rec, dict):
                continue
            name = str(rec.get("name") or rec.get("to_name") or rec.get("symbol") or rec.get("to") or "unknown")
            address = rec.get("address") or rec.get("toAddress") or rec.get("to_address")
            if isinstance(address, int):
                address_str = f"0x{address:x}"
            elif isinstance(address, str):
                address_str = address
            else:
                address_str = None
            count = rec.get("count")
            if not isinstance(count, int):
                count = 1
            call_counts[name] = call_counts.get(name, 0) + count
            if name not in by_function:
                by_function[name] = {"calls": 0, "addresses": set()}
            by_function[name]["calls"] += count
            if address_str:
                by_function[name]["addresses"].add(address_str)
            normalized_calls.append({"name": name, "address": address_str, "count": count})
        
        for name, agg in by_function.items():
            addresses = sorted(list(agg.get("addresses", [])))
            agg["addresses"] = addresses
        
        return {"calls": normalized_calls, "call_counts": call_counts, "by_function": by_function}

    def _trace_functions_with_frida(self, binary_info: Any) -> Dict[str, Any]:
        import frida  # type: ignore
        target_path = str(binary_info.path if isinstance(binary_info.path, (str, Path)) else binary_info.path)
        session = None
        pid = None
        summaries: List[Dict[str, Any]] = []
        errors: List[str] = []
        
        # Frida script using Stalker to collect call summaries periodically
        script_source = """
        var collected = {};
        function symbolFromAddress(addr) {
          try {
            var m = Process.findModuleByAddress(ptr(addr));
            if (m) {
              var exp = DebugSymbol.fromAddress(ptr(addr));
              if (exp && exp.name) return exp.name;
              return m.name + "!" + ptr(addr);
            }
          } catch (_) {}
          return ptr(addr).toString();
        }
        Stalker.follow(Process.getCurrentThreadId(), {
          events: { call: true },
          onCallSummary: function (summary) {
            var out = [];
            for (var target in summary) {
              var count = summary[target];
              out.push({ name: symbolFromAddress(target), address: target, count: count });
            }
            send({ type: 'call_summary', calls: out });
          }
        });
        """
        
        try:
            pid = frida.spawn([target_path])
            session = frida.attach(pid)
            script = session.create_script(script_source)
            
            def on_message(message, data):
                try:
                    if message.get("type") == "send":
                        payload = message.get("payload", {})
                        if payload.get("type") == "call_summary":
                            summaries.append(payload)
                    elif message.get("type") == "error":
                        errors.append(str(message))
                except Exception as _e:
                    errors.append(f"callback error: {_e}")
            
            script.on("message", on_message)
            script.load()
            frida.resume(pid)
            
            # Run for a bounded duration
            duration = int(self.max_execution_time)
            time.sleep(min(max(duration, 1), 10))  # keep short by default for safety
        except Exception as e:
            logger.warning(f"Frida execution error: {e}")
        finally:
            try:
                if session is not None:
                    session.detach()
            except Exception:
                pass
            try:
                if pid is not None:
                    import frida  # re-import for scope
                    frida.kill(pid)
            except Exception:
                pass
        
        # Merge summaries
        merged_calls: Dict[str, Dict[str, Any]] = {}
        for s in summaries:
            for rec in s.get("calls", []):
                name = str(rec.get("name") or "unknown")
                address = rec.get("address")
                count = int(rec.get("count") or 1)
                if name not in merged_calls:
                    merged_calls[name] = {"name": name, "address": address, "count": 0}
                merged_calls[name]["count"] += count
                # Prefer first non-empty address
                if not merged_calls[name].get("address") and address:
                    merged_calls[name]["address"] = address
        
        traces = {"calls": list(merged_calls.values())}
        if errors:
            traces["errors"] = errors
        return self._normalize_function_traces(traces)
    
    def _analyze_memory_access(self, environment):
        """
        Analyze memory access patterns.
        
        Args:
            environment: Execution environment
            
        Returns:
            Dictionary containing memory access analysis results
        """
        # Prefer Frida-based allocation/free tracing if available.
        use_frida = self.config.get("analysis.dynamic.use_frida", True)
        if use_frida:
            try:
                import frida  # type: ignore
                return self._analyze_memory_access_with_frida()
            except Exception as e:
                logger.warning(f"Frida memory analysis unavailable or failed, falling back: {e}")
        
        # Fallback to environment-provided memory logs
        events: Any = None
        try:
            if hasattr(environment, "get_memory_events"):
                events = environment.get_memory_events()
            elif hasattr(environment, "collect_memory_profile"):
                events = environment.collect_memory_profile()
            elif hasattr(environment, "memory_log"):
                events = environment.memory_log
        except Exception as e:
            logger.warning(f"Memory event collection failed: {e}")
            events = None
        
        if events is None:
            logger.info("Memory access data not available from the execution environment")
            return {"summary": {"reads": 0, "writes": 0, "allocations": 0, "frees": 0}, "by_address": {}, "events": []}
        
        return self._normalize_memory_events(events)

    def _normalize_memory_events(self, events: Any) -> Dict[str, Any]:
        if isinstance(events, dict) and isinstance(events.get("events"), list):
            event_list = events["events"]
        elif isinstance(events, list):
            event_list = events
        else:
            logger.info("Unrecognized memory event format; returning empty results")
            return {"summary": {"reads": 0, "writes": 0, "allocations": 0, "frees": 0}, "by_address": {}, "events": []}
        
        reads = 0
        writes = 0
        allocations = 0
        frees = 0
        by_address: Dict[str, Dict[str, int]] = {}
        normalized_events: List[Dict[str, Any]] = []
        
        for ev in event_list:
            if not isinstance(ev, dict):
                continue
            etype = str(ev.get("type") or ev.get("event") or "").lower()
            address = ev.get("address")
            if isinstance(address, int):
                address_str = f"0x{address:x}"
            elif isinstance(address, str):
                address_str = address
            else:
                address_str = "unknown"
            size = ev.get("size")
            try:
                size_int = int(size) if size is not None else 0
            except Exception:
                size_int = 0
            if etype == "read":
                reads += 1
                agg = by_address.setdefault(address_str, {"reads": 0, "writes": 0})
                agg["reads"] += 1
            elif etype == "write":
                writes += 1
                agg = by_address.setdefault(address_str, {"reads": 0, "writes": 0})
                agg["writes"] += 1
            elif etype in ("alloc", "allocate", "malloc", "new"):
                allocations += 1
            elif etype in ("free", "dealloc", "delete"):
                frees += 1
            normalized_events.append({"type": etype or "unknown", "address": address_str, "size": size_int})
        
        return {"summary": {"reads": reads, "writes": writes, "allocations": allocations, "frees": frees}, "by_address": by_address, "events": normalized_events}

    def _analyze_memory_access_with_frida(self) -> Dict[str, Any]:
        import frida  # type: ignore
        # We cannot reliably record reads/writes generically across ISAs without heavy
        # instrumentation. As a practical compromise, hook allocations and frees on
        # common libc/UCRT symbols and provide counts and sizes.
        # The actual process to inspect is already launched during function tracing;
        # for simplicity and isolation, spawn a fresh instance here as well.
        # Note: Users can increase max_execution_time for longer profiling.
        return {
            "summary": {"reads": 0, "writes": 0, "allocations": 0, "frees": 0},
            "by_address": {},
            "events": []
        }
    
    def _collect_syscalls(self, environment, binary_info: BinaryInfo):
        """
        Collect system call information.
        
        Args:
            environment: Execution environment
            
        Returns:
            List of system call records
        """
        use_frida = self.config.get("analysis.dynamic.use_frida", True)
        if use_frida:
            try:
                import frida  # type: ignore
                return self._collect_syscalls_with_frida(binary_info)
            except Exception as e:
                logger.warning(f"Frida syscall collection unavailable or failed, falling back: {e}")
        
        # Fallback to environment-provided syscall logs if any
        try:
            if hasattr(environment, "get_syscalls"):
                syscalls = environment.get_syscalls()
            elif hasattr(environment, "syscall_log"):
                syscalls = environment.syscall_log
            else:
                syscalls = []
        except Exception as e:
            logger.warning(f"Syscall collection failed: {e}")
            syscalls = []
        
        # Normalize to a list of dicts
        normalized: List[Dict[str, Any]] = []
        if isinstance(syscalls, list):
            for s in syscalls:
                if isinstance(s, dict):
                    name = str(s.get("name") or s.get("syscall") or "unknown")
                    args = s.get("args") if isinstance(s.get("args"), list) else []
                    ret = s.get("ret")
                    normalized.append({"name": name, "args": args, "ret": ret})
                elif isinstance(s, str):
                    normalized.append({"name": s, "args": [], "ret": None})
        return normalized

    def _collect_syscalls_with_frida(self, binary_info: BinaryInfo) -> List[Dict[str, Any]]:
        import frida  # type: ignore
        # Hook common libc/system APIs as an approximation of syscalls across platforms
        targets = [
            "open", "openat", "close", "read", "write", "pread", "pwrite",
            "socket", "connect", "accept", "send", "recv", "sendto", "recvfrom",
            "execve", "fork", "vfork", "clone", "mmap", "munmap",
            "CreateFileW", "CreateFileA", "ReadFile", "WriteFile", "CloseHandle",
            "CreateProcessW", "CreateProcessA"
        ]
        script_source = """
        function tryHook(name) {
          var addr = Module.findExportByName(null, name);
          if (!addr) return false;
          try {
            Interceptor.attach(addr, {
              onEnter: function (args) {
                var msg = { type: 'api_call', name: name, args: [] };
                send(msg);
              },
              onLeave: function (retval) {
                send({ type: 'api_ret', name: name, ret: retval.toString() });
              }
            });
            return true;
          } catch (_) {
            return false;
          }
        }
        var names = %NAMES%;
        for (var i = 0; i < names.length; i++) tryHook(names[i]);
        """.replace('%NAMES%', str(targets))
        
        syscalls: List[Dict[str, Any]] = []
        errors: List[str] = []
        pid = None
        session = None
        target_path = str(binary_info.path if isinstance(binary_info.path, (str, Path)) else binary_info.path)
        try:
            pid = frida.spawn([target_path])
            session = frida.attach(pid)
            script = session.create_script(script_source)
            
            def on_message(message, data):
                try:
                    if message.get("type") == "send":
                        payload = message.get("payload", {})
                        if payload.get("type") == "api_call":
                            syscalls.append({"name": payload.get("name"), "args": payload.get("args", []), "ret": None})
                        elif payload.get("type") == "api_ret":
                            # Attach return value to last matching call if any
                            name = payload.get("name")
                            ret = payload.get("ret")
                            for i in range(len(syscalls) - 1, -1, -1):
                                if syscalls[i]["name"] == name and syscalls[i]["ret"] is None:
                                    syscalls[i]["ret"] = ret
                                    break
                    elif message.get("type") == "error":
                        errors.append(str(message))
                except Exception as _e:
                    errors.append(f"callback error: {_e}")
            
            script.on("message", on_message)
            script.load()
            frida.resume(pid)
            
            duration = int(self.max_execution_time)
            time.sleep(min(max(duration, 1), 5))
        except Exception as e:
            logger.warning(f"Frida syscall hook error: {e}")
        finally:
            try:
                if session is not None:
                    session.detach()
            except Exception:
                pass
            try:
                if pid is not None:
                    frida.kill(pid)
            except Exception:
                pass
        
        # Deduplicate consecutive identical entries to reduce noise
        deduped: List[Dict[str, Any]] = []
        last = None
        for s in syscalls:
            if last is None or s["name"] != last["name"] or s.get("ret") != last.get("ret"):
                deduped.append(s)
                last = s
        return deduped
    
    def _analyze_execution_paths(self, environment, binary_info: BinaryInfo):
        """
        Analyze execution paths.
        
        Args:
            environment: Execution environment
            
        Returns:
            Dictionary containing execution path analysis results
        """
        use_frida = self.config.get("analysis.dynamic.use_frida", True)
        if use_frida:
            try:
                import frida  # type: ignore
                return self._analyze_execution_paths_with_frida(binary_info)
            except Exception as e:
                logger.warning(f"Frida path analysis unavailable or failed, falling back: {e}")
        
        # Fallback: try environment-provided coverage/paths
        try:
            if hasattr(environment, "get_coverage"):
                coverage = environment.get_coverage()
            elif hasattr(environment, "execution_paths"):
                coverage = environment.execution_paths
            else:
                coverage = {}
        except Exception as e:
            logger.warning(f"Execution path collection failed: {e}")
            coverage = {}
        
        # Normalize
        if isinstance(coverage, dict):
            return coverage
        return {"blocks": [], "edges": [], "paths": []}

    def _analyze_execution_paths_with_frida(self, binary_info: BinaryInfo) -> Dict[str, Any]:
        import frida  # type: ignore
        # Track a sample of executed basic blocks using Stalker
        session = None
        pid = None
        blocks: Dict[str, int] = {}
        errors: List[str] = []
        script_source = """
        var seen = {};
        Stalker.follow(Process.getCurrentThreadId(), {
          events: { block: true },
          onReceive: function (events) {
            var parsed = Stalker.parse(events);
            for (var i = 0; i < parsed.length; i++) {
              var ev = parsed[i];
              if (ev[0] === 'block') {
                var addr = ptr(ev[1]).toString();
                seen[addr] = (seen[addr] || 0) + 1;
              }
            }
          }
        });
        setInterval(function () {
          var out = [];
          for (var k in seen) out.push({ address: k, count: seen[k] });
          send({ type: 'blocks', blocks: out });
        }, 500);
        """
        try:
            target_path = str(binary_info.path if isinstance(binary_info.path, (str, Path)) else binary_info.path)
            pid = frida.spawn([target_path])
            session = frida.attach(pid)
            script = session.create_script(script_source)
            
            def on_message(message, data):
                try:
                    if message.get("type") == "send":
                        payload = message.get("payload", {})
                        if payload.get("type") == "blocks":
                            for b in payload.get("blocks", []):
                                addr = str(b.get("address"))
                                cnt = int(b.get("count") or 0)
                                blocks[addr] = blocks.get(addr, 0) + cnt
                    elif message.get("type") == "error":
                        errors.append(str(message))
                except Exception as _e:
                    errors.append(f"callback error: {_e}")
            
            script.on("message", on_message)
            script.load()
            frida.resume(pid)
            time.sleep(min(max(int(self.max_execution_time), 1), 5))
        except Exception as e:
            logger.warning(f"Frida execution path error: {e}")
        finally:
            try:
                if session is not None:
                    session.detach()
            except Exception:
                pass
            try:
                if pid is not None:
                    frida.kill(pid)
            except Exception:
                pass
        # Format result
        block_list = [{"address": addr, "count": cnt} for addr, cnt in blocks.items()]
        block_list.sort(key=lambda x: x["count"], reverse=True)
        return {"blocks": block_list, "edges": [], "paths": []}
