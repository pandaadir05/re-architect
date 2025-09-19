"""Storage for binary analysis comparisons."""

import os
import json
import shutil
from typing import Dict, List, Optional, Any
from datetime import datetime

from src.comparison.models import AnalysisProject, ComparisonResult


class ComparisonStore:
    """Manages storage and retrieval of binary analysis comparisons."""
    
    def __init__(self, storage_dir: str):
        """Initialize with storage directory.
        
        Args:
            storage_dir: Directory path to store comparison data
        """
        self.storage_dir = storage_dir
        self.projects_dir = os.path.join(storage_dir, "projects")
        self.comparisons_dir = os.path.join(storage_dir, "comparisons")
        
        # Create directories if they don't exist
        os.makedirs(self.projects_dir, exist_ok=True)
        os.makedirs(self.comparisons_dir, exist_ok=True)
    
    def save_project(self, project: AnalysisProject) -> str:
        """Save a project analysis to storage.
        
        Args:
            project: The analysis project to save
            
        Returns:
            The project ID
        """
        # Ensure project has an ID
        if not project.id:
            project.id = self._generate_id()
        
        # Create project directory
        project_dir = os.path.join(self.projects_dir, project.id)
        os.makedirs(project_dir, exist_ok=True)
        
        # Save project metadata
        metadata = {
            "id": project.id,
            "name": project.name,
            "binary_path": project.binary_path,
            "timestamp": project.timestamp.isoformat() if project.timestamp else datetime.now().isoformat(),
            "version": project.version,
            "description": project.description,
            "tags": project.tags
        }
        
        with open(os.path.join(project_dir, "metadata.json"), "w") as f:
            json.dump(metadata, f, indent=2)
        
        # Save analysis data
        with open(os.path.join(project_dir, "analysis.json"), "w") as f:
            json.dump(project.analysis_data, f, indent=2)
        
        return project.id
    
    def get_project(self, project_id: str) -> Optional[AnalysisProject]:
        """Retrieve a project analysis from storage.
        
        Args:
            project_id: The ID of the project to retrieve
            
        Returns:
            The retrieved project or None if not found
        """
        project_dir = os.path.join(self.projects_dir, project_id)
        
        if not os.path.exists(project_dir):
            return None
        
        # Load metadata
        try:
            with open(os.path.join(project_dir, "metadata.json"), "r") as f:
                metadata = json.load(f)
            
            # Load analysis data
            with open(os.path.join(project_dir, "analysis.json"), "r") as f:
                analysis_data = json.load(f)
            
            # Create project object
            project = AnalysisProject(
                id=metadata["id"],
                name=metadata["name"],
                binary_path=metadata.get("binary_path", ""),
                analysis_data=analysis_data,
            )
            
            # Add optional fields
            if "timestamp" in metadata:
                project.timestamp = datetime.fromisoformat(metadata["timestamp"])
            if "version" in metadata:
                project.version = metadata["version"]
            if "description" in metadata:
                project.description = metadata["description"]
            if "tags" in metadata:
                project.tags = metadata["tags"]
            
            return project
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            print(f"Error loading project {project_id}: {str(e)}")
            return None
    
    def list_projects(self) -> List[Dict[str, Any]]:
        """List all available analysis projects.
        
        Returns:
            List of project metadata dictionaries
        """
        projects = []
        
        # List directories in projects directory
        if not os.path.exists(self.projects_dir):
            return projects
            
        for project_id in os.listdir(self.projects_dir):
            project_dir = os.path.join(self.projects_dir, project_id)
            
            # Skip if not a directory
            if not os.path.isdir(project_dir):
                continue
            
            # Load metadata
            try:
                with open(os.path.join(project_dir, "metadata.json"), "r") as f:
                    metadata = json.load(f)
                projects.append(metadata)
            except (json.JSONDecodeError, FileNotFoundError):
                # Skip projects with missing or invalid metadata
                continue
        
        # Sort by timestamp (newest first)
        projects.sort(key=lambda p: p.get("timestamp", ""), reverse=True)
        return projects
    
    def delete_project(self, project_id: str) -> bool:
        """Delete a project analysis from storage.
        
        Args:
            project_id: The ID of the project to delete
            
        Returns:
            True if deletion was successful, False otherwise
        """
        project_dir = os.path.join(self.projects_dir, project_id)
        
        if not os.path.exists(project_dir):
            return False
        
        try:
            shutil.rmtree(project_dir)
            return True
        except OSError:
            return False
    
    def save_comparison(self, comparison: ComparisonResult) -> str:
        """Save a comparison result to storage.
        
        Args:
            comparison: The comparison result to save
            
        Returns:
            The comparison ID
        """
        # Ensure comparison has an ID
        if not comparison.id:
            comparison.id = self._generate_id()
        
        # Create comparison file
        comparison_path = os.path.join(self.comparisons_dir, f"{comparison.id}.json")
        
        # Convert to dictionary
        comparison_data = {
            "id": comparison.id,
            "name": comparison.name,
            "timestamp": comparison.timestamp.isoformat() if comparison.timestamp else datetime.now().isoformat(),
            "project1_id": comparison.project1_id,
            "project2_id": comparison.project2_id,
            "description": comparison.description,
            "tags": comparison.tags,
            "result_data": comparison.result_data
        }
        
        # Save to file
        with open(comparison_path, "w") as f:
            json.dump(comparison_data, f, indent=2)
        
        return comparison.id
    
    def get_comparison(self, comparison_id: str) -> Optional[ComparisonResult]:
        """Retrieve a comparison result from storage.
        
        Args:
            comparison_id: The ID of the comparison to retrieve
            
        Returns:
            The retrieved comparison or None if not found
        """
        comparison_path = os.path.join(self.comparisons_dir, f"{comparison_id}.json")
        
        if not os.path.exists(comparison_path):
            return None
        
        try:
            with open(comparison_path, "r") as f:
                data = json.load(f)
            
            # Create comparison object
            comparison = ComparisonResult(
                id=data["id"],
                name=data["name"],
                project1_id=data["project1_id"],
                project2_id=data["project2_id"],
                result_data=data["result_data"]
            )
            
            # Add optional fields
            if "timestamp" in data:
                comparison.timestamp = datetime.fromisoformat(data["timestamp"])
            if "description" in data:
                comparison.description = data["description"]
            if "tags" in data:
                comparison.tags = data["tags"]
            
            return comparison
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            print(f"Error loading comparison {comparison_id}: {str(e)}")
            return None
    
    def list_comparisons(self) -> List[Dict[str, Any]]:
        """List all available comparison results.
        
        Returns:
            List of comparison metadata dictionaries
        """
        comparisons = []
        
        # List files in comparisons directory
        if not os.path.exists(self.comparisons_dir):
            return comparisons
            
        for filename in os.listdir(self.comparisons_dir):
            if not filename.endswith(".json"):
                continue
                
            comparison_path = os.path.join(self.comparisons_dir, filename)
            
            # Load comparison data
            try:
                with open(comparison_path, "r") as f:
                    data = json.load(f)
                
                # Extract metadata
                metadata = {
                    "id": data["id"],
                    "name": data["name"],
                    "timestamp": data.get("timestamp", ""),
                    "project1_id": data["project1_id"],
                    "project2_id": data["project2_id"],
                    "description": data.get("description", ""),
                    "tags": data.get("tags", [])
                }
                
                comparisons.append(metadata)
            except (json.JSONDecodeError, FileNotFoundError, KeyError):
                # Skip comparisons with invalid data
                continue
        
        # Sort by timestamp (newest first)
        comparisons.sort(key=lambda c: c.get("timestamp", ""), reverse=True)
        return comparisons
    
    def delete_comparison(self, comparison_id: str) -> bool:
        """Delete a comparison result from storage.
        
        Args:
            comparison_id: The ID of the comparison to delete
            
        Returns:
            True if deletion was successful, False otherwise
        """
        comparison_path = os.path.join(self.comparisons_dir, f"{comparison_id}.json")
        
        if not os.path.exists(comparison_path):
            return False
        
        try:
            os.remove(comparison_path)
            return True
        except OSError:
            return False
    
    def _generate_id(self) -> str:
        """Generate a unique ID.
        
        Returns:
            A unique ID string
        """
        import uuid
        return str(uuid.uuid4())