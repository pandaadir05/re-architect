import json
import pytest
import tempfile
from unittest.mock import Mock, patch
from datetime import datetime

from flask import Flask

# Add the src directory to the Python path
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.comparison.routes import comparison_bp
from src.comparison.models import AnalysisProject, ComparisonResult, ChangeType


@pytest.fixture
def app():
    """Create a test Flask app with the comparison blueprint."""
    app = Flask(__name__)
    app.register_blueprint(comparison_bp)
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def mock_auth():
    """Mock the login_required decorator to always allow access."""
    with patch('src.comparison.routes.login_required', lambda f: f):
        yield


@pytest.fixture
def mock_store():
    """Mock the comparison store."""
    with patch('src.comparison.routes.store') as mock:
        yield mock


class TestComparisonRoutes:
    """Test cases for comparison API routes."""

    def test_list_projects_success(self, client, mock_auth, mock_store):
        """Test listing projects returns 200 with project list."""
        mock_store.list_projects.return_value = [
            {"id": "proj1", "name": "Test Project 1"},
            {"id": "proj2", "name": "Test Project 2"}
        ]
        
        response = client.get('/projects')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["id"] == "proj1"

    def test_get_project_success(self, client, mock_auth, mock_store):
        """Test getting a specific project returns 200 with project data."""
        project = AnalysisProject(
            id="proj1",
            name="Test Project",
            binary_path="/path/to/binary",
            analysis_data={"functions": []}
        )
        project.timestamp = datetime.now()
        project.version = "1.0"
        project.description = "Test description"
        project.tags = ["test", "example"]
        
        mock_store.get_project.return_value = project
        
        response = client.get('/project/proj1')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data["id"] == "proj1"
        assert data["name"] == "Test Project"
        assert "timestamp" in data
        assert data["version"] == "1.0"

    def test_get_project_not_found(self, client, mock_auth, mock_store):
        """Test getting non-existent project returns 404."""
        mock_store.get_project.return_value = None
        
        response = client.get('/project/nonexistent')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert "error" in data
        assert "not found" in data["error"]

    def test_get_project_functions_success(self, client, mock_auth, mock_store):
        """Test getting project functions returns 200 with function list."""
        project = AnalysisProject(
            id="proj1",
            name="Test Project",
            binary_path="/path/to/binary",
            analysis_data={
                "functions": [
                    {"id": "func1", "name": "main", "size": 100},
                    {"id": "func2", "name": "helper", "size": 50}
                ]
            }
        )
        mock_store.get_project.return_value = project
        
        response = client.get('/project/proj1/functions')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data["project_id"] == "proj1"
        assert "total_count" in data
        assert "functions" in data
        assert len(data["functions"]) == 2

    def test_get_project_functions_with_filters(self, client, mock_auth, mock_store):
        """Test getting project functions with filtering and pagination."""
        project = AnalysisProject(
            id="proj1",
            name="Test Project",
            binary_path="/path/to/binary",
            analysis_data={
                "functions": [
                    {"id": "func1", "name": "main_function", "size": 100},
                    {"id": "func2", "name": "helper_function", "size": 50},
                    {"id": "func3", "name": "other", "size": 25}
                ]
            }
        )
        mock_store.get_project.return_value = project
        
        # Test name filtering
        response = client.get('/project/proj1/functions?name=function')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data["functions"]) == 2  # main_function and helper_function
        
        # Test sorting by name
        response = client.get('/project/proj1/functions?sort=name')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        function_names = [f["name"] for f in data["functions"]]
        assert function_names == sorted(function_names)

    def test_create_project_success(self, client, mock_auth, mock_store):
        """Test creating a project returns 200 with project ID."""
        mock_store.save_project.return_value = "new_proj_id"
        
        project_data = {
            "name": "New Project",
            "binary_path": "/path/to/binary",
            "description": "Test project",
            "tags": ["test"]
        }
        
        response = client.post('/project', 
                             data=json.dumps(project_data),
                             content_type='application/json')
        assert response.status_code == 200  # Note: route returns 200, not 201
        
        data = json.loads(response.data)
        assert "id" in data
        assert "message" in data
        assert data["id"] == "new_proj_id"

    def test_create_project_missing_fields(self, client, mock_auth, mock_store):
        """Test creating project with missing required fields returns 400."""
        project_data = {
            "name": "New Project"
            # Missing binary_path
        }
        
        response = client.post('/project',
                             data=json.dumps(project_data),
                             content_type='application/json')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert "error" in data
        assert "required" in data["error"]

    def test_delete_project_success(self, client, mock_auth, mock_store):
        """Test deleting a project returns 200 with success message."""
        mock_store.delete_project.return_value = True
        
        response = client.delete('/project/proj1')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert "message" in data
        assert "deleted successfully" in data["message"]

    def test_delete_project_not_found(self, client, mock_auth, mock_store):
        """Test deleting non-existent project returns 404."""
        mock_store.delete_project.return_value = False
        
        response = client.delete('/project/nonexistent')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert "error" in data
        assert "not found" in data["error"]

    def test_list_comparisons_success(self, client, mock_auth, mock_store):
        """Test listing comparisons returns 200 with comparison list."""
        mock_store.list_comparisons.return_value = [
            {"id": "comp1", "name": "Comparison 1"},
            {"id": "comp2", "name": "Comparison 2"}
        ]
        
        response = client.get('/comparisons')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_get_comparison_success(self, client, mock_auth, mock_store):
        """Test getting a specific comparison returns 200 with comparison data."""
        comparison = ComparisonResult(
            base_version_id="ver1",
            target_version_id="ver2",
            base_version_name="Project 1",
            target_version_name="Project 2"
        )
        comparison.id = "comp1"
        comparison.name = "Test Comparison"
        comparison.timestamp = datetime.now()
        comparison.description = "Test description"
        comparison.tags = ["test"]
        
        mock_store.get_comparison.return_value = comparison
        
        response = client.get('/comparison/comp1')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data["id"] == "comp1"
        assert data["name"] == "Test Comparison"
        assert "timestamp" in data

    def test_get_comparison_not_found(self, client, mock_auth, mock_store):
        """Test getting non-existent comparison returns 404."""
        mock_store.get_comparison.return_value = None
        
        response = client.get('/comparison/nonexistent')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert "error" in data
        assert "not found" in data["error"]

    def test_export_analysis_success(self, client, mock_auth, mock_store):
        """Test exporting analysis returns file download."""
        project = AnalysisProject(
            id="proj1",
            name="Test Project",
            binary_path="/path/to/binary",
            analysis_data={"functions": []}
        )
        project.timestamp = datetime.now()
        project.version = "1.0"
        project.description = "Test description"
        project.tags = ["test"]
        
        mock_store.get_project.return_value = project
        
        response = client.get('/analysis/export/proj1')
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        assert 'attachment' in response.headers['Content-Disposition']

    def test_export_analysis_not_found(self, client, mock_auth, mock_store):
        """Test exporting non-existent project returns 404."""
        mock_store.get_project.return_value = None
        
        response = client.get('/analysis/export/nonexistent')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert "error" in data
        assert "not found" in data["error"]

    def test_import_analysis_success(self, client, mock_auth, mock_store):
        """Test importing analysis from JSON file returns 200."""
        mock_store.save_project.return_value = "imported_proj_id"
        
        project_data = {
            "name": "Imported Project",
            "binary_path": "/path/to/binary",
            "analysis_data": {"functions": []}
        }
        
        # Create a temporary JSON file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(project_data, f)
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                response = client.post('/analysis/import',
                                     data={'file': (f, 'test.json')},
                                     content_type='multipart/form-data')
                assert response.status_code == 200
                
                data = json.loads(response.data)
                assert "id" in data
                assert "message" in data
                assert data["id"] == "imported_proj_id"
        finally:
            import os
            os.unlink(temp_path)

    def test_import_analysis_no_file(self, client, mock_auth, mock_store):
        """Test importing analysis without file returns 400."""
        response = client.post('/analysis/import')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert "error" in data
        assert "No file provided" in data["error"]

    def test_import_analysis_invalid_json(self, client, mock_auth, mock_store):
        """Test importing invalid JSON file returns 400."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json content")
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                response = client.post('/analysis/import',
                                     data={'file': (f, 'test.json')},
                                     content_type='multipart/form-data')
                assert response.status_code == 400
                
                data = json.loads(response.data)
                assert "error" in data
                assert "Invalid JSON file" in data["error"]
        finally:
            import os
            os.unlink(temp_path)

    def test_import_analysis_wrong_extension(self, client, mock_auth, mock_store):
        """Test importing non-JSON file returns 400."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("some text content")
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                response = client.post('/analysis/import',
                                     data={'file': (f, 'test.txt')},
                                     content_type='multipart/form-data')
                assert response.status_code == 400
                
                data = json.loads(response.data)
                assert "error" in data
                assert "JSON file" in data["error"]
        finally:
            import os
            os.unlink(temp_path)
