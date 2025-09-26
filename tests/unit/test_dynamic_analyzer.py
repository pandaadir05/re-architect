import sys
import types
import pytest

from pathlib import Path

# Ensure src is importable in tests
import os
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.analysis.dynamic_analyzer import DynamicAnalyzer
from src.core.config import Config
from src.core.binary_loader import BinaryInfo, BinaryFormat, Architecture, CompilerType


class DummyEnv:
    def __init__(self, traces=None, mem_events=None, syscalls=None, coverage=None):
        self._traces = traces
        self._mem = mem_events
        self._sys = syscalls
        self._cov = coverage

    def setup(self, binary_info):
        return None

    def cleanup(self):
        return None

    def trace_functions(self, binary_info):
        return self._traces

    def get_memory_events(self):
        return self._mem

    def get_syscalls(self):
        return self._sys

    @property
    def execution_paths(self):
        return self._cov


def make_binary_info(tmp_path: Path) -> BinaryInfo:
    p = tmp_path / "dummy.bin"
    p.write_bytes(b"\x7fELF")
    return BinaryInfo(
        path=p,
        format=BinaryFormat.ELF,
        architecture=Architecture.X86_64,
        bit_width=64,
        endianness="little",
        entry_point=0,
        sections={},
        symbols={},
        compiler=CompilerType.GCC,
        stripped=True,
        is_library=False,
        imports={},
        exports=[]
    )


def test_trace_normalization_without_frida(monkeypatch, tmp_path):
    cfg = Config(None)
    cfg._config = {"analysis": {"dynamic": {"enable": True, "use_frida": False}}}
    da = DynamicAnalyzer(cfg)

    env = DummyEnv(traces=[{"name": "foo", "address": 0x401000, "count": 3}, {"name": "bar", "count": 1}])
    monkeypatch.setattr(da, "_create_execution_environment", lambda: env)

    res = da.analyze(make_binary_info(tmp_path))
    assert res["enabled"] is True
    assert "functions" in res
    calls = res["functions"].get("calls", [])
    assert any(c["name"] == "foo" and c["count"] == 3 for c in calls)
    assert any(c["name"] == "bar" for c in calls)


def test_memory_normalization_without_frida(monkeypatch, tmp_path):
    cfg = Config(None)
    cfg._config = {"analysis": {"dynamic": {"enable": True, "use_frida": False}}}
    da = DynamicAnalyzer(cfg)

    events = [
        {"type": "read", "address": 0x1000, "size": 4},
        {"type": "write", "address": 0x1000, "size": 8},
        {"type": "alloc", "address": 0x2000, "size": 16},
        {"type": "free", "address": 0x2000}
    ]
    env = DummyEnv(mem_events=events)
    monkeypatch.setattr(da, "_create_execution_environment", lambda: env)

    res = da.analyze(make_binary_info(tmp_path))
    summary = res["memory_access"]["summary"]
    assert summary["reads"] == 1
    assert summary["writes"] == 1
    assert summary["allocations"] == 1
    assert summary["frees"] == 1
    assert res["memory_access"]["by_address"]["0x1000"]["reads"] == 1


def test_syscalls_normalization_without_frida(monkeypatch, tmp_path):
    cfg = Config(None)
    cfg._config = {"analysis": {"dynamic": {"enable": True, "use_frida": False}}}
    da = DynamicAnalyzer(cfg)

    syscalls = [
        {"name": "open", "args": ["/etc/passwd"], "ret": 3},
        "close"
    ]
    env = DummyEnv(syscalls=syscalls)
    monkeypatch.setattr(da, "_create_execution_environment", lambda: env)

    res = da.analyze(make_binary_info(tmp_path))
    sc = res["syscalls"]
    assert any(s["name"] == "open" and s["ret"] == 3 for s in sc)
    assert any(s["name"] == "close" for s in sc)


def test_paths_normalization_without_frida(monkeypatch, tmp_path):
    cfg = Config(None)
    cfg._config = {"analysis": {"dynamic": {"enable": True, "use_frida": False}}}
    da = DynamicAnalyzer(cfg)

    coverage = {"blocks": [{"address": "0x1000", "count": 5}]}
    env = DummyEnv(coverage=coverage)
    monkeypatch.setattr(da, "_create_execution_environment", lambda: env)

    res = da.analyze(make_binary_info(tmp_path))
    assert res["execution_paths"].get("blocks")
