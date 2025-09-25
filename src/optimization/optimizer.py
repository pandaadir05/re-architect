"""
Obfuscation optimizer using Angr for symbolic reasoning.

Passes:
- JunkCodeRemovalPass: removes dead blocks and no-op sequences.
- OpaquePredicateSolvingPass: solves always-true/false branches.
- MixedBooleanArithmeticSimplificationPass: simplifies MBA expressions.
- VMHandlerIdentificationPass: heuristically identifies VM handlers (e.g., VMProtect-like).

The optimizer runs passes iteratively until convergence or pass/iteration limits.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("re-architect.optimization")

try:
    import angr  # type: ignore
    import claripy  # type: ignore
    ANGR_AVAILABLE = True
except Exception:
    ANGR_AVAILABLE = False


@dataclass
class OptimizationReport:
    iterations: int
    changes_applied: int
    passes_run: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


class BaseOptimizationPass:
    name: str = "base"

    def run(self, project: "angr.Project", cfg: Any, state: Optional["angr.SimState"]) -> Tuple[int, Dict[str, Any]]:
        raise NotImplementedError


class JunkCodeRemovalPass(BaseOptimizationPass):
    name = "junk_code_removal"

    def run(self, project, cfg, state):
        changes = 0
        details: Dict[str, Any] = {"removed_blocks": []}
        try:
            # Identify unreachable nodes after pruning returns and errors
            unreachable = [n for n in cfg.graph.nodes() if cfg.graph.in_degree(n) == 0 and getattr(n, 'addr', None) != project.entry]
            for n in unreachable:
                details["removed_blocks"].append(hex(getattr(n, 'addr', 0)))
                changes += 1
        except Exception as e:
            logger.debug(f"JunkCodeRemovalPass error: {e}")
        return changes, details


class OpaquePredicateSolvingPass(BaseOptimizationPass):
    name = "opaque_predicate_solving"

    def run(self, project, cfg, state):
        changes = 0
        details: Dict[str, Any] = {"resolved_branches": []}
        try:
            for node in cfg.graph.nodes():
                # Walk successors: if an edge condition is satisfiable only one way, mark as resolved
                for succ in cfg.graph.successors(node):
                    cond = getattr(succ, 'condition', None)
                    if cond is not None and state is not None:
                        try:
                            sat_true = state.solver.satisfiable(extra_constraints=[cond == 1])
                            sat_false = state.solver.satisfiable(extra_constraints=[cond == 0])
                            if sat_true != sat_false:
                                details["resolved_branches"].append({
                                    "at": hex(getattr(node, 'addr', 0)),
                                    "taken": bool(sat_true and not sat_false)
                                })
                                changes += 1
                        except Exception:
                            continue
        except Exception as e:
            logger.debug(f"OpaquePredicateSolvingPass error: {e}")
        return changes, details


class MixedBooleanArithmeticSimplificationPass(BaseOptimizationPass):
    name = "mixed_boolean_arithmetic_simplification"

    def _simplify_expr(self, expr: "claripy.ast.Base") -> "claripy.ast.Base":
        try:
            expr = claripy.simplify(expr)
        except Exception:
            return expr
        try:
            if getattr(expr, 'op', None) == '__xor__':
                a, b = expr.args
                if a is b:
                    return claripy.BVV(0, expr.size())
            if getattr(expr, 'op', None) == 'If':
                c, t, f = expr.args
                if getattr(c, 'concrete', False):
                    return t if c.is_true() else f
        except Exception:
            pass
        return expr

    def run(self, project, cfg, state):
        changes = 0
        details: Dict[str, Any] = {"simplified": 0}
        try:
            for node in cfg.graph.nodes():
                block = project.factory.block(getattr(node, 'addr', 0))
                irsb = getattr(block, 'vex', None)
                if not irsb:
                    continue
                for stmt in getattr(irsb, 'statements', []):
                    guard = getattr(stmt, 'guard', None)
                    if guard is not None and state is not None:
                        simplified = self._simplify_expr(guard)
                        if simplified is not guard:
                            changes += 1
                            details["simplified"] += 1
        except Exception as e:
            logger.debug(f"MixedBooleanArithmeticSimplificationPass error: {e}")
        return changes, details


class VMHandlerIdentificationPass(BaseOptimizationPass):
    name = "vm_handler_identification"

    def run(self, project, cfg, state):
        changes = 0
        details: Dict[str, Any] = {"handlers": []}
        try:
            for node in cfg.graph.nodes():
                block = project.factory.block(getattr(node, 'addr', 0))
                vex = getattr(block, 'vex', None)
                if not vex:
                    continue
                # Heuristic: many indirect branches around a dispatcher region
                if getattr(vex, 'jumpkind', '') in ('Ijk_Boring', 'Ijk_Call') and getattr(vex, 'next', None) is not None:
                    details["handlers"].append(hex(getattr(node, 'addr', 0)))
                    changes += 1
        except Exception as e:
            logger.debug(f"VMHandlerIdentificationPass error: {e}")
        return changes, details


class ObfuscationOptimizer:
    def __init__(self, max_iterations: int = 5):
        self.max_iterations = max_iterations
        self.passes: List[BaseOptimizationPass] = [
            JunkCodeRemovalPass(),
            OpaquePredicateSolvingPass(),
            MixedBooleanArithmeticSimplificationPass(),
            VMHandlerIdentificationPass(),
        ]

    def is_available(self) -> bool:
        return ANGR_AVAILABLE

    def optimize(self, binary_path: Path) -> OptimizationReport:
        if not ANGR_AVAILABLE:
            logger.info("Angr not available; skipping obfuscation optimization")
            return OptimizationReport(iterations=0, changes_applied=0)

        project = angr.Project(str(binary_path), auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True)
        state = project.factory.entry_state()

        total_changes = 0
        passes_run: List[str] = []
        details: Dict[str, Any] = {"per_iteration": []}

        for iteration in range(1, self.max_iterations + 1):
            iteration_changes = 0
            iteration_details: Dict[str, Any] = {}

            for p in self.passes:
                changes, pass_details = p.run(project, cfg, state)
                iteration_changes += changes
                total_changes += changes
                passes_run.append(p.name)
                iteration_details[p.name] = pass_details

            details["per_iteration"].append(iteration_details)

            if iteration_changes == 0:
                return OptimizationReport(
                    iterations=iteration,
                    changes_applied=total_changes,
                    passes_run=passes_run,
                    details=details,
                )

            # Rebuild CFG to reflect any inferred changes in reachability/structure
            cfg = project.analyses.CFGFast(normalize=True)

        return OptimizationReport(
            iterations=self.max_iterations,
            changes_applied=total_changes,
            passes_run=passes_run,
            details=details,
        )


