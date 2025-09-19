"""Models for binary analysis comparisons."""

import os
import json
import uuid
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Any, Union, Tuple


class ChangeType(Enum):
    """Types of changes between binary versions."""

    ADDED = auto()
    REMOVED = auto()
    MODIFIED = auto()
    RENAMED = auto()
    UNCHANGED = auto()


class AnalysisProject:
    """Represents a binary analysis project with versioning capabilities."""

    def __init__(
        self,
        name: str,
        description: str = "",
        binary_path: Optional[str] = None,
        project_id: Optional[str] = None,
    ):
        """Initialize a project."""
        self.project_id = project_id or str(uuid.uuid4())
        self.name = name
        self.description = description
        self.binary_path = binary_path
        self.created_at = datetime.utcnow()
        self.updated_at = self.created_at
        self.versions: Dict[str, "AnalysisVersion"] = {}
        
    def add_version(
        self,
        version_name: str,
        binary_path: str,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "AnalysisVersion":
        """Add a new version to the project."""
        if version_name in self.versions:
            raise ValueError(f"Version '{version_name}' already exists")

        version = AnalysisVersion(
            project_id=self.project_id,
            version_name=version_name,
            binary_path=binary_path,
            description=description,
            metadata=metadata or {},
        )
        
        self.versions[version_name] = version
        self.updated_at = datetime.utcnow()
        return version
    
    def get_version(self, version_name: str) -> "AnalysisVersion":
        """Get a specific version by name."""
        if version_name not in self.versions:
            raise ValueError(f"Version '{version_name}' does not exist")
        
        return self.versions[version_name]
    
    def list_versions(self) -> List["AnalysisVersion"]:
        """List all versions in the project, sorted by creation date."""
        return sorted(
            self.versions.values(),
            key=lambda v: v.created_at
        )
    
    def compare_versions(
        self,
        base_version: str,
        target_version: str,
    ) -> "ComparisonResult":
        """Compare two versions and generate a comparison result."""
        if base_version not in self.versions:
            raise ValueError(f"Base version '{base_version}' does not exist")
            
        if target_version not in self.versions:
            raise ValueError(f"Target version '{target_version}' does not exist")
            
        base = self.versions[base_version]
        target = self.versions[target_version]
        
        from src.comparison.comparator import BinaryComparator
        comparator = BinaryComparator()
        return comparator.compare(base, target)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "project_id": self.project_id,
            "name": self.name,
            "description": self.description,
            "binary_path": self.binary_path,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "versions": {
                name: version.to_dict()
                for name, version in self.versions.items()
            },
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisProject":
        """Create from dictionary representation."""
        project = cls(
            name=data["name"],
            description=data["description"],
            binary_path=data.get("binary_path"),
            project_id=data["project_id"],
        )
        
        project.created_at = datetime.fromisoformat(data["created_at"])
        project.updated_at = datetime.fromisoformat(data["updated_at"])
        
        # Recreate versions
        for version_name, version_data in data.get("versions", {}).items():
            version = AnalysisVersion.from_dict(version_data)
            project.versions[version_name] = version
            
        return project
    
    def save(self, output_dir: str) -> str:
        """Save project to a JSON file."""
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, f"{self.project_id}.json")
        
        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
            
        return file_path
    
    @classmethod
    def load(cls, file_path: str) -> "AnalysisProject":
        """Load project from a JSON file."""
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        return cls.from_dict(data)


class AnalysisVersion:
    """Represents a single version of a binary analysis."""

    def __init__(
        self,
        project_id: str,
        version_name: str,
        binary_path: str,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        version_id: Optional[str] = None,
    ):
        """Initialize a version."""
        self.version_id = version_id or str(uuid.uuid4())
        self.project_id = project_id
        self.version_name = version_name
        self.binary_path = binary_path
        self.description = description
        self.metadata = metadata or {}
        self.created_at = datetime.utcnow()
        
        # Analysis results
        self.functions: Dict[str, "FunctionInfo"] = {}
        self.structures: Dict[str, "StructureInfo"] = {}
        self.call_graph: Dict[str, List[str]] = {}  # function_id -> [called_function_ids]
        self.performance_metrics: Dict[str, Dict[str, Any]] = {}
        
    def add_function(self, function: "FunctionInfo") -> None:
        """Add or update a function in the analysis."""
        self.functions[function.function_id] = function
        
    def add_structure(self, structure: "StructureInfo") -> None:
        """Add or update a structure in the analysis."""
        self.structures[structure.structure_id] = structure
        
    def add_call(self, caller_id: str, callee_id: str) -> None:
        """Add a function call to the call graph."""
        if caller_id not in self.call_graph:
            self.call_graph[caller_id] = []
            
        if callee_id not in self.call_graph[caller_id]:
            self.call_graph[caller_id].append(callee_id)
            
    def set_performance_metrics(
        self, 
        function_id: str, 
        metrics: Dict[str, Any]
    ) -> None:
        """Set performance metrics for a function."""
        self.performance_metrics[function_id] = metrics
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "version_id": self.version_id,
            "project_id": self.project_id,
            "version_name": self.version_name,
            "binary_path": self.binary_path,
            "description": self.description,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "functions": {
                fid: f.to_dict() for fid, f in self.functions.items()
            },
            "structures": {
                sid: s.to_dict() for sid, s in self.structures.items()
            },
            "call_graph": self.call_graph,
            "performance_metrics": self.performance_metrics,
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisVersion":
        """Create from dictionary representation."""
        version = cls(
            project_id=data["project_id"],
            version_name=data["version_name"],
            binary_path=data["binary_path"],
            description=data["description"],
            metadata=data.get("metadata", {}),
            version_id=data["version_id"],
        )
        
        version.created_at = datetime.fromisoformat(data["created_at"])
        
        # Recreate functions
        for fid, func_data in data.get("functions", {}).items():
            function = FunctionInfo.from_dict(func_data)
            version.functions[fid] = function
            
        # Recreate structures
        for sid, struct_data in data.get("structures", {}).items():
            structure = StructureInfo.from_dict(struct_data)
            version.structures[sid] = structure
            
        # Copy call graph and performance metrics
        version.call_graph = data.get("call_graph", {})
        version.performance_metrics = data.get("performance_metrics", {})
        
        return version


class FunctionInfo:
    """Information about a function in a binary."""

    def __init__(
        self,
        name: str,
        address: int,
        size: int,
        signature: Optional[str] = None,
        function_id: Optional[str] = None,
        complexity: Optional[int] = None,
        decompiled_code: Optional[str] = None,
        summary: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ):
        """Initialize function information."""
        self.function_id = function_id or str(uuid.uuid4())
        self.name = name
        self.address = address
        self.size = size
        self.signature = signature
        self.complexity = complexity
        self.decompiled_code = decompiled_code
        self.summary = summary
        self.tags = tags or []
        self.parameters: List["ParameterInfo"] = []
        self.local_vars: List["VariableInfo"] = []
        
    def add_parameter(self, param: "ParameterInfo") -> None:
        """Add a parameter to the function."""
        self.parameters.append(param)
        
    def add_local_var(self, var: "VariableInfo") -> None:
        """Add a local variable to the function."""
        self.local_vars.append(var)
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "function_id": self.function_id,
            "name": self.name,
            "address": self.address,
            "size": self.size,
            "signature": self.signature,
            "complexity": self.complexity,
            "decompiled_code": self.decompiled_code,
            "summary": self.summary,
            "tags": self.tags,
            "parameters": [p.to_dict() for p in self.parameters],
            "local_vars": [v.to_dict() for v in self.local_vars],
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FunctionInfo":
        """Create from dictionary representation."""
        function = cls(
            name=data["name"],
            address=data["address"],
            size=data["size"],
            signature=data.get("signature"),
            function_id=data["function_id"],
            complexity=data.get("complexity"),
            decompiled_code=data.get("decompiled_code"),
            summary=data.get("summary"),
            tags=data.get("tags", []),
        )
        
        # Recreate parameters and local variables
        for param_data in data.get("parameters", []):
            param = ParameterInfo.from_dict(param_data)
            function.add_parameter(param)
            
        for var_data in data.get("local_vars", []):
            var = VariableInfo.from_dict(var_data)
            function.add_local_var(var)
            
        return function


class ParameterInfo:
    """Information about a function parameter."""

    def __init__(
        self,
        name: str,
        type_name: str,
        position: int,
        size: int,
    ):
        """Initialize parameter information."""
        self.name = name
        self.type_name = type_name
        self.position = position
        self.size = size
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "type_name": self.type_name,
            "position": self.position,
            "size": self.size,
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ParameterInfo":
        """Create from dictionary representation."""
        return cls(
            name=data["name"],
            type_name=data["type_name"],
            position=data["position"],
            size=data["size"],
        )


class VariableInfo:
    """Information about a local variable."""

    def __init__(
        self,
        name: str,
        type_name: str,
        size: int,
        is_stack: bool = True,
    ):
        """Initialize variable information."""
        self.name = name
        self.type_name = type_name
        self.size = size
        self.is_stack = is_stack
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "type_name": self.type_name,
            "size": self.size,
            "is_stack": self.is_stack,
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VariableInfo":
        """Create from dictionary representation."""
        return cls(
            name=data["name"],
            type_name=data["type_name"],
            size=data["size"],
            is_stack=data["is_stack"],
        )


class StructureInfo:
    """Information about a data structure in a binary."""

    def __init__(
        self,
        name: str,
        size: int,
        structure_id: Optional[str] = None,
        is_union: bool = False,
    ):
        """Initialize structure information."""
        self.structure_id = structure_id or str(uuid.uuid4())
        self.name = name
        self.size = size
        self.is_union = is_union
        self.fields: List["StructureField"] = []
        
    def add_field(self, field: "StructureField") -> None:
        """Add a field to the structure."""
        self.fields.append(field)
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "structure_id": self.structure_id,
            "name": self.name,
            "size": self.size,
            "is_union": self.is_union,
            "fields": [f.to_dict() for f in self.fields],
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StructureInfo":
        """Create from dictionary representation."""
        structure = cls(
            name=data["name"],
            size=data["size"],
            structure_id=data["structure_id"],
            is_union=data["is_union"],
        )
        
        # Recreate fields
        for field_data in data.get("fields", []):
            field = StructureField.from_dict(field_data)
            structure.add_field(field)
            
        return structure


class StructureField:
    """Information about a field in a data structure."""

    def __init__(
        self,
        name: str,
        type_name: str,
        offset: int,
        size: int,
    ):
        """Initialize field information."""
        self.name = name
        self.type_name = type_name
        self.offset = offset
        self.size = size
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "type_name": self.type_name,
            "offset": self.offset,
            "size": self.size,
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StructureField":
        """Create from dictionary representation."""
        return cls(
            name=data["name"],
            type_name=data["type_name"],
            offset=data["offset"],
            size=data["size"],
        )


class ComparisonResult:
    """Results of comparing two binary analysis versions."""

    def __init__(
        self,
        base_version_id: str,
        target_version_id: str,
        base_version_name: str,
        target_version_name: str,
    ):
        """Initialize comparison result."""
        self.base_version_id = base_version_id
        self.target_version_id = target_version_id
        self.base_version_name = base_version_name
        self.target_version_name = target_version_name
        self.created_at = datetime.utcnow()
        
        # Changes between versions
        self.function_changes: Dict[str, Tuple[ChangeType, Optional[str]]] = {}
        self.structure_changes: Dict[str, Tuple[ChangeType, Optional[str]]] = {}
        self.call_graph_changes: List[Dict[str, Any]] = []
        self.metric_changes: Dict[str, Dict[str, Any]] = {}
        
        # Similarity scores (0.0 to 1.0)
        self.overall_similarity = 0.0
        self.function_similarity = 0.0
        self.structure_similarity = 0.0
        self.call_graph_similarity = 0.0
        
    def add_function_change(
        self,
        function_id: str,
        change_type: ChangeType,
        corresponding_id: Optional[str] = None,
    ) -> None:
        """Add a function change to the result."""
        self.function_changes[function_id] = (change_type, corresponding_id)
        
    def add_structure_change(
        self,
        structure_id: str,
        change_type: ChangeType,
        corresponding_id: Optional[str] = None,
    ) -> None:
        """Add a structure change to the result."""
        self.structure_changes[structure_id] = (change_type, corresponding_id)
        
    def add_call_graph_change(
        self,
        caller_id: str,
        callee_id: str,
        change_type: ChangeType,
    ) -> None:
        """Add a call graph change to the result."""
        self.call_graph_changes.append({
            "caller_id": caller_id,
            "callee_id": callee_id,
            "change_type": change_type.name,
        })
        
    def add_metric_change(
        self,
        function_id: str,
        metric_name: str,
        base_value: Any,
        target_value: Any,
        change_percentage: float,
    ) -> None:
        """Add a performance metric change to the result."""
        if function_id not in self.metric_changes:
            self.metric_changes[function_id] = {}
            
        self.metric_changes[function_id][metric_name] = {
            "base_value": base_value,
            "target_value": target_value,
            "change_percentage": change_percentage,
        }
        
    def set_similarity_scores(
        self,
        overall: float,
        function: float,
        structure: float,
        call_graph: float,
    ) -> None:
        """Set similarity scores for the comparison."""
        self.overall_similarity = overall
        self.function_similarity = function
        self.structure_similarity = structure
        self.call_graph_similarity = call_graph
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        # Convert ChangeType enum to string for serialization
        function_changes = {
            f_id: (ct.name, corr_id)
            for f_id, (ct, corr_id) in self.function_changes.items()
        }
        
        structure_changes = {
            s_id: (ct.name, corr_id)
            for s_id, (ct, corr_id) in self.structure_changes.items()
        }
        
        return {
            "base_version_id": self.base_version_id,
            "target_version_id": self.target_version_id,
            "base_version_name": self.base_version_name,
            "target_version_name": self.target_version_name,
            "created_at": self.created_at.isoformat(),
            "function_changes": function_changes,
            "structure_changes": structure_changes,
            "call_graph_changes": self.call_graph_changes,
            "metric_changes": self.metric_changes,
            "overall_similarity": self.overall_similarity,
            "function_similarity": self.function_similarity,
            "structure_similarity": self.structure_similarity,
            "call_graph_similarity": self.call_graph_similarity,
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComparisonResult":
        """Create from dictionary representation."""
        result = cls(
            base_version_id=data["base_version_id"],
            target_version_id=data["target_version_id"],
            base_version_name=data["base_version_name"],
            target_version_name=data["target_version_name"],
        )
        
        result.created_at = datetime.fromisoformat(data["created_at"])
        
        # Convert string back to ChangeType enum
        for f_id, (ct_str, corr_id) in data.get("function_changes", {}).items():
            result.function_changes[f_id] = (ChangeType[ct_str], corr_id)
            
        for s_id, (ct_str, corr_id) in data.get("structure_changes", {}).items():
            result.structure_changes[s_id] = (ChangeType[ct_str], corr_id)
            
        result.call_graph_changes = data.get("call_graph_changes", [])
        result.metric_changes = data.get("metric_changes", {})
        
        # Set similarity scores
        result.overall_similarity = data.get("overall_similarity", 0.0)
        result.function_similarity = data.get("function_similarity", 0.0)
        result.structure_similarity = data.get("structure_similarity", 0.0)
        result.call_graph_similarity = data.get("call_graph_similarity", 0.0)
        
        return result