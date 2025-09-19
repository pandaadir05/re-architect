"""Binary comparison utilities."""

import difflib
from typing import Dict, List, Set, Tuple, Optional, Any

from src.comparison.models import (
    AnalysisVersion,
    ComparisonResult,
    ChangeType,
    FunctionInfo,
    StructureInfo,
)


class BinaryComparator:
    """Compares two binary analysis versions to find differences."""

    def __init__(self, 
                 name_similarity_threshold: float = 0.85,
                 code_similarity_threshold: float = 0.75):
        """Initialize comparator with similarity thresholds."""
        self.name_similarity_threshold = name_similarity_threshold
        self.code_similarity_threshold = code_similarity_threshold
    
    def compare(
        self, 
        base_version: AnalysisVersion,
        target_version: AnalysisVersion,
    ) -> ComparisonResult:
        """Compare two binary analysis versions."""
        result = ComparisonResult(
            base_version_id=base_version.version_id,
            target_version_id=target_version.version_id,
            base_version_name=base_version.version_name,
            target_version_name=target_version.version_name,
        )
        
        # Compare functions
        function_matches = self._match_functions(
            base_version.functions, 
            target_version.functions
        )
        
        self._analyze_function_changes(
            base_version.functions,
            target_version.functions,
            function_matches,
            result,
        )
        
        # Compare structures
        structure_matches = self._match_structures(
            base_version.structures,
            target_version.structures,
        )
        
        self._analyze_structure_changes(
            base_version.structures,
            target_version.structures,
            structure_matches,
            result,
        )
        
        # Compare call graphs
        self._analyze_call_graph_changes(
            base_version.call_graph,
            target_version.call_graph,
            function_matches,
            result,
        )
        
        # Compare performance metrics
        self._analyze_performance_changes(
            base_version.performance_metrics,
            target_version.performance_metrics,
            function_matches,
            result,
        )
        
        # Calculate overall similarity scores
        self._calculate_similarity_scores(
            base_version,
            target_version,
            function_matches,
            structure_matches,
            result,
        )
        
        return result
    
    def _match_functions(
        self,
        base_functions: Dict[str, FunctionInfo],
        target_functions: Dict[str, FunctionInfo],
    ) -> Dict[str, str]:
        """Match functions between versions based on similarity."""
        matches: Dict[str, str] = {}  # base_id -> target_id
        
        # First, try to match by exact name
        for base_id, base_func in base_functions.items():
            for target_id, target_func in target_functions.items():
                if (base_func.name == target_func.name and 
                    target_id not in matches.values()):
                    matches[base_id] = target_id
                    break
        
        # For remaining functions, try to match by name similarity and signature
        unmatched_base_ids = [
            fid for fid in base_functions.keys() if fid not in matches
        ]
        
        matched_target_ids = set(matches.values())
        unmatched_target_ids = [
            fid for fid in target_functions.keys() 
            if fid not in matched_target_ids
        ]
        
        for base_id in unmatched_base_ids:
            base_func = base_functions[base_id]
            best_match = None
            best_score = 0.0
            
            for target_id in unmatched_target_ids:
                target_func = target_functions[target_id]
                
                # Calculate name similarity
                name_similarity = difflib.SequenceMatcher(
                    None, base_func.name, target_func.name
                ).ratio()
                
                # Calculate code similarity if available
                code_similarity = 0.0
                if (base_func.decompiled_code and 
                    target_func.decompiled_code):
                    code_similarity = difflib.SequenceMatcher(
                        None, 
                        base_func.decompiled_code, 
                        target_func.decompiled_code
                    ).ratio()
                
                # Weight and combine similarity scores
                combined_score = (
                    0.7 * name_similarity + 
                    0.3 * code_similarity
                )
                
                if (combined_score > best_score and 
                    combined_score > self.name_similarity_threshold):
                    best_score = combined_score
                    best_match = target_id
            
            if best_match and best_match not in matches.values():
                matches[base_id] = best_match
                unmatched_target_ids.remove(best_match)
        
        return matches
    
    def _match_structures(
        self,
        base_structures: Dict[str, StructureInfo],
        target_structures: Dict[str, StructureInfo],
    ) -> Dict[str, str]:
        """Match structures between versions based on similarity."""
        matches: Dict[str, str] = {}  # base_id -> target_id
        
        # First, try to match by exact name
        for base_id, base_struct in base_structures.items():
            for target_id, target_struct in target_structures.items():
                if (base_struct.name == target_struct.name and 
                    target_id not in matches.values()):
                    matches[base_id] = target_id
                    break
        
        # For remaining structures, try to match by field similarity
        unmatched_base_ids = [
            sid for sid in base_structures.keys() if sid not in matches
        ]
        
        matched_target_ids = set(matches.values())
        unmatched_target_ids = [
            sid for sid in target_structures.keys() 
            if sid not in matched_target_ids
        ]
        
        for base_id in unmatched_base_ids:
            base_struct = base_structures[base_id]
            best_match = None
            best_score = 0.0
            
            for target_id in unmatched_target_ids:
                target_struct = target_structures[target_id]
                
                # Calculate name similarity
                name_similarity = difflib.SequenceMatcher(
                    None, base_struct.name, target_struct.name
                ).ratio()
                
                # Calculate field similarity
                field_similarity = self._calculate_field_similarity(
                    base_struct, target_struct
                )
                
                # Weight and combine similarity scores
                combined_score = (
                    0.4 * name_similarity + 
                    0.6 * field_similarity
                )
                
                if (combined_score > best_score and 
                    combined_score > self.name_similarity_threshold):
                    best_score = combined_score
                    best_match = target_id
            
            if best_match and best_match not in matches.values():
                matches[base_id] = best_match
                unmatched_target_ids.remove(best_match)
        
        return matches
    
    def _calculate_field_similarity(
        self,
        base_struct: StructureInfo,
        target_struct: StructureInfo,
    ) -> float:
        """Calculate similarity between structure fields."""
        if not base_struct.fields or not target_struct.fields:
            return 0.0
        
        # Compare field names and types
        base_field_names = [f.name for f in base_struct.fields]
        target_field_names = [f.name for f in target_struct.fields]
        
        base_field_types = [f.type_name for f in base_struct.fields]
        target_field_types = [f.type_name for f in target_struct.fields]
        
        # Calculate Jaccard similarity for names and types
        common_names = set(base_field_names) & set(target_field_names)
        name_similarity = len(common_names) / (
            len(set(base_field_names) | set(target_field_names))
        )
        
        common_types = set(base_field_types) & set(target_field_types)
        type_similarity = len(common_types) / (
            len(set(base_field_types) | set(target_field_types))
        )
        
        # Weight and combine similarities
        return 0.7 * name_similarity + 0.3 * type_similarity
    
    def _analyze_function_changes(
        self,
        base_functions: Dict[str, FunctionInfo],
        target_functions: Dict[str, FunctionInfo],
        function_matches: Dict[str, str],
        result: ComparisonResult,
    ) -> None:
        """Analyze changes between functions in two versions."""
        # Find added, removed, modified, and unchanged functions
        for base_id, base_func in base_functions.items():
            if base_id in function_matches:
                target_id = function_matches[base_id]
                target_func = target_functions[target_id]
                
                if self._is_function_modified(base_func, target_func):
                    result.add_function_change(
                        base_id, ChangeType.MODIFIED, target_id
                    )
                elif base_func.name != target_func.name:
                    result.add_function_change(
                        base_id, ChangeType.RENAMED, target_id
                    )
                else:
                    result.add_function_change(
                        base_id, ChangeType.UNCHANGED, target_id
                    )
            else:
                result.add_function_change(base_id, ChangeType.REMOVED)
                
        # Find added functions in target version
        matched_target_ids = set(function_matches.values())
        for target_id, target_func in target_functions.items():
            if target_id not in matched_target_ids:
                result.add_function_change(target_id, ChangeType.ADDED)
    
    def _is_function_modified(
        self,
        base_func: FunctionInfo,
        target_func: FunctionInfo,
    ) -> bool:
        """Check if a function has been modified."""
        # If the size or complexity changed, consider it modified
        if base_func.size != target_func.size:
            return True
            
        if (base_func.complexity is not None and 
            target_func.complexity is not None and
            base_func.complexity != target_func.complexity):
            return True
            
        # If the signature changed, consider it modified
        if base_func.signature != target_func.signature:
            return True
            
        # If parameters changed, consider it modified
        if len(base_func.parameters) != len(target_func.parameters):
            return True
            
        # If the decompiled code is available, compare it
        if (base_func.decompiled_code and target_func.decompiled_code):
            code_similarity = difflib.SequenceMatcher(
                None, 
                base_func.decompiled_code, 
                target_func.decompiled_code
            ).ratio()
            
            if code_similarity < self.code_similarity_threshold:
                return True
                
        return False
    
    def _analyze_structure_changes(
        self,
        base_structures: Dict[str, StructureInfo],
        target_structures: Dict[str, StructureInfo],
        structure_matches: Dict[str, str],
        result: ComparisonResult,
    ) -> None:
        """Analyze changes between structures in two versions."""
        # Find added, removed, modified, and unchanged structures
        for base_id, base_struct in base_structures.items():
            if base_id in structure_matches:
                target_id = structure_matches[base_id]
                target_struct = target_structures[target_id]
                
                if self._is_structure_modified(base_struct, target_struct):
                    result.add_structure_change(
                        base_id, ChangeType.MODIFIED, target_id
                    )
                elif base_struct.name != target_struct.name:
                    result.add_structure_change(
                        base_id, ChangeType.RENAMED, target_id
                    )
                else:
                    result.add_structure_change(
                        base_id, ChangeType.UNCHANGED, target_id
                    )
            else:
                result.add_structure_change(base_id, ChangeType.REMOVED)
                
        # Find added structures in target version
        matched_target_ids = set(structure_matches.values())
        for target_id, target_struct in target_structures.items():
            if target_id not in matched_target_ids:
                result.add_structure_change(target_id, ChangeType.ADDED)
    
    def _is_structure_modified(
        self,
        base_struct: StructureInfo,
        target_struct: StructureInfo,
    ) -> bool:
        """Check if a structure has been modified."""
        # If the size or is_union changed, consider it modified
        if base_struct.size != target_struct.size:
            return True
            
        if base_struct.is_union != target_struct.is_union:
            return True
            
        # If the number of fields changed, consider it modified
        if len(base_struct.fields) != len(target_struct.fields):
            return True
            
        # Check for field differences
        base_fields = {
            (f.name, f.type_name, f.offset, f.size) 
            for f in base_struct.fields
        }
        
        target_fields = {
            (f.name, f.type_name, f.offset, f.size) 
            for f in target_struct.fields
        }
        
        if base_fields != target_fields:
            return True
            
        return False
    
    def _analyze_call_graph_changes(
        self,
        base_call_graph: Dict[str, List[str]],
        target_call_graph: Dict[str, List[str]],
        function_matches: Dict[str, str],
        result: ComparisonResult,
    ) -> None:
        """Analyze changes in call graph between versions."""
        # Create reverse mapping for faster lookup
        target_to_base = {
            target_id: base_id 
            for base_id, target_id in function_matches.items()
        }
        
        # Check for removed calls
        for base_caller_id, base_callees in base_call_graph.items():
            # Skip if the caller function itself was removed
            if base_caller_id not in function_matches:
                continue
                
            target_caller_id = function_matches[base_caller_id]
            target_callees = target_call_graph.get(target_caller_id, [])
            
            # Map base callee IDs to target IDs if they exist
            mapped_target_callees = []
            for base_callee_id in base_callees:
                if base_callee_id in function_matches:
                    mapped_target_callees.append(
                        function_matches[base_callee_id]
                    )
            
            # Find removed calls
            for base_callee_id in base_callees:
                if (base_callee_id in function_matches and
                    function_matches[base_callee_id] not in target_callees):
                    result.add_call_graph_change(
                        base_caller_id,
                        base_callee_id,
                        ChangeType.REMOVED
                    )
        
        # Check for added calls
        for target_caller_id, target_callees in target_call_graph.items():
            # Skip if the caller function is new (was added)
            if target_caller_id not in target_to_base:
                continue
                
            base_caller_id = target_to_base[target_caller_id]
            base_callees = base_call_graph.get(base_caller_id, [])
            
            # Map target callee IDs to base IDs if they exist
            mapped_base_callees = []
            for target_callee_id in target_callees:
                if target_callee_id in target_to_base:
                    mapped_base_callees.append(
                        target_to_base[target_callee_id]
                    )
            
            # Find added calls
            for target_callee_id in target_callees:
                if (target_callee_id in target_to_base and
                    target_to_base[target_callee_id] not in base_callees):
                    result.add_call_graph_change(
                        base_caller_id,
                        target_to_base[target_callee_id],
                        ChangeType.ADDED
                    )
    
    def _analyze_performance_changes(
        self,
        base_metrics: Dict[str, Dict[str, Any]],
        target_metrics: Dict[str, Dict[str, Any]],
        function_matches: Dict[str, str],
        result: ComparisonResult,
    ) -> None:
        """Analyze changes in performance metrics between versions."""
        for base_func_id, base_func_metrics in base_metrics.items():
            # Skip if the function was removed
            if base_func_id not in function_matches:
                continue
                
            target_func_id = function_matches[base_func_id]
            target_func_metrics = target_metrics.get(target_func_id, {})
            
            # Compare metrics
            for metric_name, base_value in base_func_metrics.items():
                if metric_name in target_func_metrics:
                    target_value = target_func_metrics[metric_name]
                    
                    # Skip if not numeric
                    if not (isinstance(base_value, (int, float)) and 
                           isinstance(target_value, (int, float))):
                        continue
                        
                    # Calculate percentage change
                    if base_value != 0:
                        change_pct = (
                            (target_value - base_value) / abs(base_value) * 100
                        )
                    else:
                        # Avoid division by zero
                        change_pct = float('inf') if target_value != 0 else 0.0
                        
                    result.add_metric_change(
                        base_func_id,
                        metric_name,
                        base_value,
                        target_value,
                        change_pct
                    )
    
    def _calculate_similarity_scores(
        self,
        base_version: AnalysisVersion,
        target_version: AnalysisVersion,
        function_matches: Dict[str, str],
        structure_matches: Dict[str, str],
        result: ComparisonResult,
    ) -> None:
        """Calculate various similarity scores between versions."""
        # Function similarity
        if base_version.functions:
            function_similarity = len(function_matches) / len(base_version.functions)
        else:
            function_similarity = 1.0 if not target_version.functions else 0.0
            
        # Structure similarity
        if base_version.structures:
            structure_similarity = len(structure_matches) / len(base_version.structures)
        else:
            structure_similarity = 1.0 if not target_version.structures else 0.0
            
        # Call graph similarity
        call_graph_similarity = self._calculate_call_graph_similarity(
            base_version.call_graph,
            target_version.call_graph,
            function_matches
        )
        
        # Overall similarity (weighted average)
        overall_similarity = (
            0.5 * function_similarity +
            0.3 * structure_similarity +
            0.2 * call_graph_similarity
        )
        
        result.set_similarity_scores(
            overall=overall_similarity,
            function=function_similarity,
            structure=structure_similarity,
            call_graph=call_graph_similarity
        )
    
    def _calculate_call_graph_similarity(
        self,
        base_call_graph: Dict[str, List[str]],
        target_call_graph: Dict[str, List[str]],
        function_matches: Dict[str, str],
    ) -> float:
        """Calculate similarity between call graphs."""
        if not base_call_graph:
            return 1.0 if not target_call_graph else 0.0
        
        # Count preserved edges
        preserved_edges = 0
        total_base_edges = 0
        
        for base_caller_id, base_callees in base_call_graph.items():
            total_base_edges += len(base_callees)
            
            # Skip if the caller was removed
            if base_caller_id not in function_matches:
                continue
                
            target_caller_id = function_matches[base_caller_id]
            target_callees = target_call_graph.get(target_caller_id, [])
            
            for base_callee_id in base_callees:
                # Skip if the callee was removed
                if base_callee_id not in function_matches:
                    continue
                    
                target_callee_id = function_matches[base_callee_id]
                
                if target_callee_id in target_callees:
                    preserved_edges += 1
        
        if total_base_edges == 0:
            return 1.0
            
        return preserved_edges / total_base_edges