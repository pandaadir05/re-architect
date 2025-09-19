"""Binary comparison analyzer module.

This module implements algorithms for comparing binary analysis results
between different versions of a program.
"""

from typing import Dict, List, Any, Optional, Tuple, Set
import difflib
from dataclasses import dataclass


@dataclass
class FunctionDiff:
    """Represents differences between two versions of a function."""
    
    name: str
    address_before: str
    address_after: str
    size_before: int
    size_after: int
    complexity_before: int
    complexity_after: int
    size_change: int
    complexity_change: int
    code_similarity: float  # 0-1 score of similarity
    match_confidence: float  # 0-1 confidence in the match
    
    # Lists of call addresses that were added/removed
    added_calls: List[str]
    removed_calls: List[str]
    
    # If available, detailed instruction differences
    instruction_changes: Optional[Dict[str, Any]] = None


@dataclass
class StructureDiff:
    """Represents differences between two versions of a data structure."""
    
    name: str
    type_before: str
    type_after: str
    size_before: int
    size_after: int
    size_change: int
    
    # Track changes to members
    added_members: List[Dict[str, Any]]
    removed_members: List[Dict[str, Any]]
    modified_members: List[Dict[str, Any]]
    
    match_confidence: float  # 0-1 confidence in the match


@dataclass
class BinaryDiff:
    """Top-level diff between two binary analyses."""
    
    # Basic binary info
    name: str
    version_before: str
    version_after: str
    
    # Function changes
    added_functions: List[Dict[str, Any]]
    removed_functions: List[Dict[str, Any]]
    modified_functions: List[FunctionDiff]
    
    # Structure changes
    added_structures: List[Dict[str, Any]]
    removed_structures: List[Dict[str, Any]]
    modified_structures: List[StructureDiff]
    
    # Overall statistics
    function_count_before: int
    function_count_after: int
    structure_count_before: int
    structure_count_after: int
    
    # Security changes
    security_issues_added: List[Dict[str, Any]]
    security_issues_removed: List[Dict[str, Any]]


class BinaryComparisonAnalyzer:
    """Analyzes and compares two binary analysis results."""
    
    def __init__(self, threshold: float = 0.7):
        """Initialize with similarity threshold.
        
        Args:
            threshold: Minimum similarity score to consider two functions a match
        """
        self.similarity_threshold = threshold
    
    def compare_binaries(self, before: Dict[str, Any], after: Dict[str, Any]) -> BinaryDiff:
        """Compare two binary analysis results.
        
        Args:
            before: Analysis results from first binary version
            after: Analysis results from second binary version
            
        Returns:
            BinaryDiff object with comparison details
        """
        # Match functions between the two binaries
        function_matches = self._match_functions(before.get('functions', []), 
                                                after.get('functions', []))
        
        # Compare matched functions
        modified_functions = []
        for before_func, after_func, confidence in function_matches:
            diff = self._compare_functions(before_func, after_func, confidence)
            modified_functions.append(diff)
        
        # Find added/removed functions
        before_matched = {f['id'] for f, _, _ in function_matches}
        after_matched = {f['id'] for _, f, _ in function_matches}
        
        added_functions = [f for f in after.get('functions', []) 
                           if f['id'] not in after_matched]
        removed_functions = [f for f in before.get('functions', []) 
                             if f['id'] not in before_matched]
        
        # Match and compare data structures
        struct_matches = self._match_structures(before.get('data_structures', []),
                                               after.get('data_structures', []))
        
        # Compare matched structures
        modified_structures = []
        for before_struct, after_struct, confidence in struct_matches:
            diff = self._compare_structures(before_struct, after_struct, confidence)
            modified_structures.append(diff)
        
        # Find added/removed structures
        before_struct_matched = {s['name'] for s, _, _ in struct_matches}
        after_struct_matched = {s['name'] for _, s, _ in struct_matches}
        
        added_structures = [s for s in after.get('data_structures', []) 
                           if s['name'] not in after_struct_matched]
        removed_structures = [s for s in before.get('data_structures', []) 
                             if s['name'] not in before_struct_matched]
        
        # Compare security issues
        security_issues_added, security_issues_removed = self._compare_security_issues(
            before.get('security_issues', []),
            after.get('security_issues', [])
        )
        
        # Create the binary diff
        return BinaryDiff(
            name=after.get('name', 'Unknown Binary'),
            version_before=before.get('version', 'Unknown'),
            version_after=after.get('version', 'Unknown'),
            added_functions=added_functions,
            removed_functions=removed_functions,
            modified_functions=modified_functions,
            added_structures=added_structures,
            removed_structures=removed_structures,
            modified_structures=modified_structures,
            function_count_before=len(before.get('functions', [])),
            function_count_after=len(after.get('functions', [])),
            structure_count_before=len(before.get('data_structures', [])),
            structure_count_after=len(after.get('data_structures', [])),
            security_issues_added=security_issues_added,
            security_issues_removed=security_issues_removed
        )
    
    def _match_functions(self, before: List[Dict[str, Any]], 
                        after: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Dict[str, Any], float]]:
        """Match functions between two binaries using name and signature similarity.
        
        Args:
            before: List of functions from first binary
            after: List of functions from second binary
            
        Returns:
            List of tuples (before_func, after_func, confidence)
        """
        matches = []
        
        # First, try to match by name (exact match)
        name_matches = {}
        for before_func in before:
            for after_func in after:
                if before_func['name'] == after_func['name']:
                    name_matches.setdefault(before_func['id'], []).append(
                        (after_func, 0.8)  # Base confidence for name match
                    )
        
        # For each before_func with name matches, find the best match
        matched_after_funcs = set()
        
        for before_id, candidates in name_matches.items():
            before_func = next(f for f in before if f['id'] == before_id)
            
            best_match = None
            best_confidence = 0
            
            for after_func, base_confidence in candidates:
                if after_func['id'] in matched_after_funcs:
                    continue
                
                # Calculate similarity based on code content if available
                if ('decompiled_code' in before_func and 
                    'decompiled_code' in after_func):
                    code_sim = self._calculate_code_similarity(
                        before_func['decompiled_code'],
                        after_func['decompiled_code']
                    )
                    # Weighted combination of name match and code similarity
                    confidence = 0.4 * base_confidence + 0.6 * code_sim
                else:
                    confidence = base_confidence
                
                if confidence > best_confidence and confidence >= self.similarity_threshold:
                    best_match = after_func
                    best_confidence = confidence
            
            if best_match:
                matches.append((before_func, best_match, best_confidence))
                matched_after_funcs.add(best_match['id'])
        
        # For functions without name matches, try to match by code similarity
        unmatched_before = [f for f in before if f['id'] not in name_matches]
        unmatched_after = [f for f in after if f['id'] not in matched_after_funcs]
        
        if unmatched_before and unmatched_after:
            # Only proceed with expensive comparison if both sets are non-empty
            for before_func in unmatched_before:
                best_match = None
                best_confidence = 0
                
                for after_func in unmatched_after:
                    # Calculate similarity based on available metrics
                    metrics_sim = self._calculate_metrics_similarity(before_func, after_func)
                    
                    # If code is available, use it to refine the similarity
                    if ('decompiled_code' in before_func and 
                        'decompiled_code' in after_func):
                        code_sim = self._calculate_code_similarity(
                            before_func['decompiled_code'],
                            after_func['decompiled_code']
                        )
                        # Weight code similarity higher than metrics
                        confidence = 0.3 * metrics_sim + 0.7 * code_sim
                    else:
                        confidence = metrics_sim
                    
                    if confidence > best_confidence and confidence >= self.similarity_threshold:
                        best_match = after_func
                        best_confidence = confidence
                
                if best_match:
                    matches.append((before_func, best_match, best_confidence))
                    unmatched_after.remove(best_match)
        
        return matches
    
    def _calculate_code_similarity(self, code1: str, code2: str) -> float:
        """Calculate similarity between two code snippets.
        
        Args:
            code1: First code snippet
            code2: Second code snippet
            
        Returns:
            Similarity score between 0 and 1
        """
        # Use difflib's SequenceMatcher for string similarity
        matcher = difflib.SequenceMatcher(None, code1, code2)
        return matcher.ratio()
    
    def _calculate_metrics_similarity(self, func1: Dict[str, Any], 
                                     func2: Dict[str, Any]) -> float:
        """Calculate similarity based on function metrics.
        
        Args:
            func1: First function data
            func2: Second function data
            
        Returns:
            Similarity score between 0 and 1
        """
        # Compare based on complexity, size, and call patterns
        total_score = 0
        total_weight = 0
        
        # Compare complexity if available
        if 'complexity' in func1 and 'complexity' in func2:
            max_complexity = max(func1['complexity'], func2['complexity'])
            if max_complexity > 0:
                complexity_diff = abs(func1['complexity'] - func2['complexity']) / max_complexity
                complexity_sim = 1 - min(complexity_diff, 1.0)
                total_score += 0.3 * complexity_sim
                total_weight += 0.3
        
        # Compare size if available
        if 'size' in func1 and 'size' in func2:
            max_size = max(func1['size'], func2['size'])
            if max_size > 0:
                size_diff = abs(func1['size'] - func2['size']) / max_size
                size_sim = 1 - min(size_diff, 1.0)
                total_score += 0.3 * size_sim
                total_weight += 0.3
        
        # Compare call counts if available
        if 'callsTo' in func1 and 'callsTo' in func2:
            max_calls = max(func1['callsTo'], func2['callsTo'])
            if max_calls > 0:
                calls_diff = abs(func1['callsTo'] - func2['callsTo']) / max_calls
                calls_sim = 1 - min(calls_diff, 1.0)
                total_score += 0.2 * calls_sim
                total_weight += 0.2
        
        # If we have no metrics to compare, return low similarity
        if total_weight == 0:
            return 0.1
            
        # Normalize score by total weight
        return total_score / total_weight
    
    def _compare_functions(self, before: Dict[str, Any], 
                          after: Dict[str, Any], 
                          confidence: float) -> FunctionDiff:
        """Compare two functions in detail.
        
        Args:
            before: Function data from first binary
            after: Function data from second binary
            confidence: Match confidence score
            
        Returns:
            FunctionDiff object with detailed comparison
        """
        # Extract added and removed calls
        added_calls = []
        removed_calls = []
        
        # If we have call graph data
        before_calls = set()
        after_calls = set()
        
        if 'call_graph' in before and 'links' in before['call_graph']:
            before_calls = {link['target'] for link in before['call_graph']['links'] 
                          if link['source'] == before['id']}
        
        if 'call_graph' in after and 'links' in after['call_graph']:
            after_calls = {link['target'] for link in after['call_graph']['links'] 
                         if link['source'] == after['id']}
        
        added_calls = list(after_calls - before_calls)
        removed_calls = list(before_calls - after_calls)
        
        # Calculate code similarity if available
        code_similarity = 0.0
        if 'decompiled_code' in before and 'decompiled_code' in after:
            code_similarity = self._calculate_code_similarity(
                before['decompiled_code'],
                after['decompiled_code']
            )
        
        # Compare instructions if available
        instruction_changes = None
        if 'disassembly' in before and 'disassembly' in after:
            instruction_changes = self._compare_instructions(
                before['disassembly'],
                after['disassembly']
            )
        
        # Create function diff
        return FunctionDiff(
            name=after['name'],
            address_before=before.get('address', 'Unknown'),
            address_after=after.get('address', 'Unknown'),
            size_before=before.get('size', 0),
            size_after=after.get('size', 0),
            complexity_before=before.get('complexity', 0),
            complexity_after=after.get('complexity', 0),
            size_change=after.get('size', 0) - before.get('size', 0),
            complexity_change=after.get('complexity', 0) - before.get('complexity', 0),
            code_similarity=code_similarity,
            match_confidence=confidence,
            added_calls=added_calls,
            removed_calls=removed_calls,
            instruction_changes=instruction_changes
        )
    
    def _compare_instructions(self, before: List[Dict[str, Any]], 
                             after: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compare function instructions.
        
        Args:
            before: List of instructions from first function
            after: List of instructions from second function
            
        Returns:
            Dictionary with instruction diff details
        """
        # Extract instruction text for comparison
        before_instr = [f"{i['instruction']} {i.get('comment', '')}" for i in before]
        after_instr = [f"{i['instruction']} {i.get('comment', '')}" for i in after]
        
        # Get unified diff
        diff = list(difflib.unified_diff(before_instr, after_instr, n=1))
        
        # Count added, modified, and removed instructions
        added = sum(1 for d in diff if d.startswith('+') and not d.startswith('+++'))
        removed = sum(1 for d in diff if d.startswith('-') and not d.startswith('---'))
        
        return {
            'added_count': added,
            'removed_count': removed,
            'modified_count': min(added, removed),  # Conservative estimate of modifications
            'total_before': len(before),
            'total_after': len(after),
            'change_ratio': (added + removed) / max(len(before) + len(after), 1)
        }
    
    def _match_structures(self, before: List[Dict[str, Any]], 
                         after: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Dict[str, Any], float]]:
        """Match data structures between two binaries.
        
        Args:
            before: List of data structures from first binary
            after: List of data structures from second binary
            
        Returns:
            List of tuples (before_struct, after_struct, confidence)
        """
        matches = []
        
        # First match by exact name
        matched_after = set()
        
        for before_struct in before:
            for after_struct in after:
                if (after_struct['name'] == before_struct['name'] and 
                    after_struct['name'] not in matched_after):
                    # Calculate similarity based on members
                    confidence = self._calculate_structure_similarity(before_struct, after_struct)
                    
                    if confidence >= self.similarity_threshold:
                        matches.append((before_struct, after_struct, confidence))
                        matched_after.add(after_struct['name'])
                        break
        
        # For unmatched structures, try fuzzy matching
        unmatched_before = [s for s in before if s['name'] not in {b['name'] for b, _, _ in matches}]
        unmatched_after = [s for s in after if s['name'] not in matched_after]
        
        for before_struct in unmatched_before:
            best_match = None
            best_confidence = 0
            
            for after_struct in unmatched_after:
                # Try name similarity and member similarity
                name_sim = difflib.SequenceMatcher(None, 
                                                  before_struct['name'], 
                                                  after_struct['name']).ratio()
                
                if name_sim > 0.7:  # Only consider if names are somewhat similar
                    member_sim = self._calculate_structure_similarity(before_struct, after_struct)
                    confidence = 0.4 * name_sim + 0.6 * member_sim
                    
                    if confidence > best_confidence and confidence >= self.similarity_threshold:
                        best_match = after_struct
                        best_confidence = confidence
            
            if best_match:
                matches.append((before_struct, best_match, best_confidence))
                unmatched_after.remove(best_match)
                
        return matches
    
    def _calculate_structure_similarity(self, struct1: Dict[str, Any], 
                                       struct2: Dict[str, Any]) -> float:
        """Calculate similarity between two data structures.
        
        Args:
            struct1: First structure data
            struct2: Second structure data
            
        Returns:
            Similarity score between 0 and 1
        """
        # Compare based on size and members
        if 'members' not in struct1 or 'members' not in struct2:
            # If no member info, compare basic properties
            if struct1['type'] == struct2['type']:
                # Same type, give some base similarity
                return 0.7
            return 0.3
        
        # Count matching members (by name and type)
        members1 = {m['name']: m['type'] for m in struct1['members']}
        members2 = {m['name']: m['type'] for m in struct2['members']}
        
        # Count exact matches (same name and type)
        exact_matches = sum(1 for name, type_ in members1.items() 
                           if name in members2 and members2[name] == type_)
        
        # Count name matches (same name, different type)
        name_matches = sum(1 for name in members1 
                          if name in members2 and members2[name] != members1[name])
        
        # Total possible matches
        total = max(len(members1), len(members2))
        
        if total == 0:
            return 0.5  # Empty structures are somewhat similar
            
        # Weight exact matches higher than name-only matches
        similarity = (exact_matches + 0.5 * name_matches) / total
        
        # If the types match, boost the similarity
        if struct1['type'] == struct2['type']:
            similarity = min(1.0, similarity + 0.2)
            
        return similarity
    
    def _compare_structures(self, before: Dict[str, Any], 
                           after: Dict[str, Any], 
                           confidence: float) -> StructureDiff:
        """Compare two data structures in detail.
        
        Args:
            before: Structure data from first binary
            after: Structure data from second binary
            confidence: Match confidence score
            
        Returns:
            StructureDiff object with detailed comparison
        """
        # Extract added, removed, and modified members
        added_members = []
        removed_members = []
        modified_members = []
        
        if 'members' in before and 'members' in after:
            before_members = {m['name']: m for m in before['members']}
            after_members = {m['name']: m for m in after['members']}
            
            # Find added and removed members
            added_names = set(after_members.keys()) - set(before_members.keys())
            removed_names = set(before_members.keys()) - set(after_members.keys())
            common_names = set(before_members.keys()) & set(after_members.keys())
            
            added_members = [after_members[name] for name in added_names]
            removed_members = [before_members[name] for name in removed_names]
            
            # Find modified members
            for name in common_names:
                if before_members[name]['type'] != after_members[name]['type']:
                    modified_members.append({
                        'name': name,
                        'type_before': before_members[name]['type'],
                        'type_after': after_members[name]['type'],
                        'offset_before': before_members[name].get('offset', 0),
                        'offset_after': after_members[name].get('offset', 0)
                    })
                elif before_members[name].get('offset', 0) != after_members[name].get('offset', 0):
                    modified_members.append({
                        'name': name,
                        'type': before_members[name]['type'],
                        'offset_before': before_members[name].get('offset', 0),
                        'offset_after': after_members[name].get('offset', 0)
                    })
        
        # Create structure diff
        return StructureDiff(
            name=after['name'],
            type_before=before.get('type', 'unknown'),
            type_after=after.get('type', 'unknown'),
            size_before=before.get('size', 0),
            size_after=after.get('size', 0),
            size_change=after.get('size', 0) - before.get('size', 0),
            added_members=added_members,
            removed_members=removed_members,
            modified_members=modified_members,
            match_confidence=confidence
        )
    
    def _compare_security_issues(self, before: List[Dict[str, Any]], 
                                after: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Compare security issues between two binaries.
        
        Args:
            before: Security issues from first binary
            after: Security issues from second binary
            
        Returns:
            Tuple of (added_issues, removed_issues)
        """
        # Convert to sets for easy comparison
        # Use tuples of (type, description) as unique identifiers
        before_issues = {(issue['type'], issue.get('description', '')): issue for issue in before}
        after_issues = {(issue['type'], issue.get('description', '')): issue for issue in after}
        
        # Find added and removed issues
        added_keys = set(after_issues.keys()) - set(before_issues.keys())
        removed_keys = set(before_issues.keys()) - set(after_issues.keys())
        
        added_issues = [after_issues[key] for key in added_keys]
        removed_issues = [before_issues[key] for key in removed_keys]
        
        return added_issues, removed_issues