"""API routes for project comparison."""

from flask import Blueprint, jsonify, request, send_file, g
import os
from datetime import datetime
import json

from src.auth.middleware import login_required
from src.comparison.store import ComparisonStore
from src.comparison.models import (
    AnalysisProject, 
    AnalysisVersion,
    ComparisonResult, 
    FunctionInfo,
    StructureInfo,
    ParameterInfo,
    VariableInfo,
    StructureField,
    ChangeType
)
from src.comparison.comparator import BinaryComparator

# Create blueprint
comparison_bp = Blueprint('comparison', __name__)

# Initialize the comparison store
STORAGE_DIR = os.environ.get('RE_ARCHITECT_DATA_DIR', os.path.expanduser('~/.re-architect/data'))
store = ComparisonStore(os.path.join(STORAGE_DIR, 'comparisons'))

@comparison_bp.route('/projects', methods=['GET'])
@login_required
def list_projects():
    """List all saved analysis projects."""
    projects = store.list_projects()
    return jsonify(projects)

@comparison_bp.route('/project/<project_id>', methods=['GET'])
@login_required
def get_project(project_id):
    """Get a specific analysis project."""
    project = store.get_project(project_id)
    if not project:
        return jsonify({"error": f"Project {project_id} not found"}), 404
    
    # Convert to dictionary
    project_dict = {
        "id": project.id,
        "name": project.name,
        "binary_path": project.binary_path,
        "timestamp": project.timestamp.isoformat() if project.timestamp else None,
        "version": project.version,
        "description": project.description,
        "tags": project.tags
    }
    
    # Include analysis_data only if explicitly requested
    if request.args.get('include_analysis') == 'true':
        project_dict["analysis_data"] = project.analysis_data
    
    return jsonify(project_dict)

@comparison_bp.route('/project/<project_id>/functions', methods=['GET'])
@login_required
def get_project_functions(project_id):
    """Get all functions from a specific project."""
    project = store.get_project(project_id)
    if not project:
        return jsonify({"error": f"Project {project_id} not found"}), 404
    
    functions = project.analysis_data.get('functions', [])
    
    # Apply optional filtering
    name_filter = request.args.get('name')
    if name_filter:
        functions = [f for f in functions if name_filter.lower() in f.get('name', '').lower()]
    
    # Apply optional sorting
    sort_by = request.args.get('sort')
    if sort_by == 'name':
        functions = sorted(functions, key=lambda f: f.get('name', ''))
    elif sort_by == 'size':
        functions = sorted(functions, key=lambda f: f.get('size', 0), reverse=True)
    elif sort_by == 'complexity':
        functions = sorted(functions, key=lambda f: f.get('complexity', 0), reverse=True)
    
    # Apply optional pagination
    try:
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 50))
        start = (page - 1) * page_size
        end = start + page_size
        paginated_functions = functions[start:end]
    except ValueError:
        paginated_functions = functions
    
    return jsonify({
        "project_id": project_id,
        "total_count": len(functions),
        "functions": paginated_functions
    })

@comparison_bp.route('/project/<project_id>/structures', methods=['GET'])
@login_required
def get_project_structures(project_id):
    """Get all data structures from a specific project."""
    project = store.get_project(project_id)
    if not project:
        return jsonify({"error": f"Project {project_id} not found"}), 404
    
    structures = project.analysis_data.get('structures', [])
    
    # Apply optional filtering
    name_filter = request.args.get('name')
    if name_filter:
        structures = [s for s in structures if name_filter.lower() in s.get('name', '').lower()]
    
    # Apply optional sorting
    sort_by = request.args.get('sort')
    if sort_by == 'name':
        structures = sorted(structures, key=lambda s: s.get('name', ''))
    elif sort_by == 'size':
        structures = sorted(structures, key=lambda s: s.get('size', 0), reverse=True)
    
    # Apply optional pagination
    try:
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 50))
        start = (page - 1) * page_size
        end = start + page_size
        paginated_structures = structures[start:end]
    except ValueError:
        paginated_structures = structures
    
    return jsonify({
        "project_id": project_id,
        "total_count": len(structures),
        "structures": paginated_structures
    })

@comparison_bp.route('/project', methods=['POST'])
@login_required
def create_project():
    """Create a new analysis project."""
    data = request.json
    
    # Check required fields
    if not data.get('name') or not data.get('binary_path'):
        return jsonify({"error": "Name and binary_path are required"}), 400
    
    # Create project
    project = AnalysisProject(
        project_id=data.get('id'),
        name=data['name'],
        description=data.get('description', ''),
        binary_path=data['binary_path']
    )
    
    # Add optional fields
    if 'timestamp' in data:
        try:
            project.timestamp = datetime.fromisoformat(data['timestamp'])
        except ValueError:
            pass
    if 'version' in data:
        project.version = data['version']
    if 'description' in data:
        project.description = data['description']
    if 'tags' in data:
        project.tags = data['tags']
    
    # Save project
    project_id = store.save_project(project)
    
    return jsonify({
        "id": project_id,
        "message": "Project created successfully"
    })

@comparison_bp.route('/project/<project_id>', methods=['DELETE'])
@login_required
def delete_project(project_id):
    """Delete an analysis project."""
    success = store.delete_project(project_id)
    if not success:
        return jsonify({"error": f"Project {project_id} not found"}), 404
    
    return jsonify({"message": f"Project {project_id} deleted successfully"})

@comparison_bp.route('/comparisons', methods=['GET'])
@login_required
def list_comparisons():
    """List all saved comparisons."""
    comparisons = store.list_comparisons()
    return jsonify(comparisons)

@comparison_bp.route('/comparison/<comparison_id>', methods=['GET'])
@login_required
def get_comparison(comparison_id):
    """Get a specific comparison."""
    comparison = store.get_comparison(comparison_id)
    if not comparison:
        return jsonify({"error": f"Comparison {comparison_id} not found"}), 404
    
    # Convert to dictionary
    comparison_dict = {
        "id": comparison.id,
        "name": comparison.name,
        "timestamp": comparison.timestamp.isoformat() if comparison.timestamp else None,
        "project1_id": comparison.base_version_id,
        "project2_id": comparison.target_version_id,
        "description": comparison.description,
        "tags": comparison.tags,
    }
    
    # Include result_data only if explicitly requested
    if request.args.get('include_results') == 'true':
        comparison_dict["result_data"] = comparison.result_data
    
    return jsonify(comparison_dict)

@comparison_bp.route('/comparison/<comparison_id>/functions', methods=['GET'])
@login_required
def get_comparison_functions(comparison_id):
    """Get function changes from a specific comparison."""
    comparison = store.get_comparison(comparison_id)
    if not comparison:
        return jsonify({"error": f"Comparison {comparison_id} not found"}), 404
    
    # Get function changes from result data
    function_changes = []
    if comparison.function_changes:
        # Convert ChangeType enum to string for serialization
        for func_id, (change_type, corresponding_id) in comparison.function_changes.items():
            change = {
                "function_id": func_id,
                "change_type": change_type.name,
                "corresponding_id": corresponding_id,
            }
            
            # Get function details from project1 or project2
            if change_type in [ChangeType.REMOVED, ChangeType.MODIFIED, ChangeType.RENAMED, ChangeType.UNCHANGED]:
                # Function exists in project1
                project1 = store.get_project(comparison.project1_id)
                if project1:
                    for func in project1.analysis_data.get('functions', []):
                        if func.get('id') == func_id:
                            change["function_details"] = func
                            break
            
            if change_type in [ChangeType.ADDED, ChangeType.MODIFIED, ChangeType.RENAMED, ChangeType.UNCHANGED]:
                # Function exists in project2
                if corresponding_id:
                    project2 = store.get_project(comparison.project2_id)
                    if project2:
                        for func in project2.analysis_data.get('functions', []):
                            if func.get('id') == corresponding_id:
                                change["corresponding_function_details"] = func
                                break
            
            function_changes.append(change)
    
    # Apply optional filtering
    change_type_filter = request.args.get('change_type')
    if change_type_filter:
        try:
            change_type = ChangeType[change_type_filter.upper()]
            function_changes = [c for c in function_changes 
                                if c['change_type'] == change_type.name]
        except KeyError:
            pass
    
    # Apply optional name filtering
    name_filter = request.args.get('name')
    if name_filter:
        function_changes = [c for c in function_changes 
                            if ('function_details' in c and 
                                name_filter.lower() in c['function_details'].get('name', '').lower())]
    
    # Apply optional sorting
    sort_by = request.args.get('sort')
    if sort_by == 'name':
        function_changes = sorted(
            function_changes, 
            key=lambda c: c.get('function_details', {}).get('name', '') 
                if 'function_details' in c 
                else c.get('corresponding_function_details', {}).get('name', '')
        )
    elif sort_by == 'change_type':
        function_changes = sorted(function_changes, key=lambda c: c['change_type'])
    
    # Apply optional pagination
    try:
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 50))
        start = (page - 1) * page_size
        end = start + page_size
        paginated_changes = function_changes[start:end]
    except ValueError:
        paginated_changes = function_changes
    
    return jsonify({
        "comparison_id": comparison_id,
        "total_count": len(function_changes),
        "function_changes": paginated_changes
    })

@comparison_bp.route('/comparison/<comparison_id>/structures', methods=['GET'])
@login_required
def get_comparison_structures(comparison_id):
    """Get structure changes from a specific comparison."""
    comparison = store.get_comparison(comparison_id)
    if not comparison:
        return jsonify({"error": f"Comparison {comparison_id} not found"}), 404
    
    # Get structure changes from result data
    structure_changes = []
    if comparison.structure_changes:
        # Convert ChangeType enum to string for serialization
        for struct_id, (change_type, corresponding_id) in comparison.structure_changes.items():
            change = {
                "structure_id": struct_id,
                "change_type": change_type.name,
                "corresponding_id": corresponding_id,
            }
            
            # Get structure details from project1 or project2
            if change_type in [ChangeType.REMOVED, ChangeType.MODIFIED, ChangeType.RENAMED, ChangeType.UNCHANGED]:
                # Structure exists in project1
                project1 = store.get_project(comparison.project1_id)
                if project1:
                    for struct in project1.analysis_data.get('structures', []):
                        if struct.get('id') == struct_id:
                            change["structure_details"] = struct
                            break
            
            if change_type in [ChangeType.ADDED, ChangeType.MODIFIED, ChangeType.RENAMED, ChangeType.UNCHANGED]:
                # Structure exists in project2
                if corresponding_id:
                    project2 = store.get_project(comparison.project2_id)
                    if project2:
                        for struct in project2.analysis_data.get('structures', []):
                            if struct.get('id') == corresponding_id:
                                change["corresponding_structure_details"] = struct
                                break
            
            structure_changes.append(change)
    
    # Apply optional filtering
    change_type_filter = request.args.get('change_type')
    if change_type_filter:
        try:
            change_type = ChangeType[change_type_filter.upper()]
            structure_changes = [c for c in structure_changes 
                                 if c['change_type'] == change_type.name]
        except KeyError:
            pass
    
    # Apply optional name filtering
    name_filter = request.args.get('name')
    if name_filter:
        structure_changes = [c for c in structure_changes 
                             if ('structure_details' in c and 
                                 name_filter.lower() in c['structure_details'].get('name', '').lower())]
    
    # Apply optional sorting
    sort_by = request.args.get('sort')
    if sort_by == 'name':
        structure_changes = sorted(
            structure_changes, 
            key=lambda c: c.get('structure_details', {}).get('name', '') 
                if 'structure_details' in c 
                else c.get('corresponding_structure_details', {}).get('name', '')
        )
    elif sort_by == 'change_type':
        structure_changes = sorted(structure_changes, key=lambda c: c['change_type'])
    
    # Apply optional pagination
    try:
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 50))
        start = (page - 1) * page_size
        end = start + page_size
        paginated_changes = structure_changes[start:end]
    except ValueError:
        paginated_changes = structure_changes
    
    return jsonify({
        "comparison_id": comparison_id,
        "total_count": len(structure_changes),
        "structure_changes": paginated_changes
    })

@comparison_bp.route('/comparison/<comparison_id>/metrics', methods=['GET'])
@login_required
def get_comparison_metrics(comparison_id):
    """Get performance metric changes from a specific comparison."""
    comparison = store.get_comparison(comparison_id)
    if not comparison:
        return jsonify({"error": f"Comparison {comparison_id} not found"}), 404
    
    # Get metric changes
    metric_changes = []
    if comparison.metric_changes:
        for func_id, metrics in comparison.metric_changes.items():
            func_name = "Unknown"
            
            # Try to get function name from project1
            project1 = store.get_project(comparison.project1_id)
            if project1:
                for func in project1.analysis_data.get('functions', []):
                    if func.get('id') == func_id:
                        func_name = func.get('name', 'Unknown')
                        break
            
            for metric_name, values in metrics.items():
                change = {
                    "function_id": func_id,
                    "function_name": func_name,
                    "metric_name": metric_name,
                    "base_value": values["base_value"],
                    "target_value": values["target_value"],
                    "change_percentage": values["change_percentage"]
                }
                metric_changes.append(change)
    
    # Apply optional function filtering
    func_filter = request.args.get('function')
    if func_filter:
        metric_changes = [c for c in metric_changes 
                          if func_filter.lower() in c['function_name'].lower()]
    
    # Apply optional metric filtering
    metric_filter = request.args.get('metric')
    if metric_filter:
        metric_changes = [c for c in metric_changes 
                         if metric_filter.lower() == c['metric_name'].lower()]
    
    # Apply optional sorting
    sort_by = request.args.get('sort')
    if sort_by == 'function_name':
        metric_changes = sorted(metric_changes, key=lambda c: c['function_name'])
    elif sort_by == 'metric_name':
        metric_changes = sorted(metric_changes, key=lambda c: c['metric_name'])
    elif sort_by == 'change':
        metric_changes = sorted(metric_changes, 
                              key=lambda c: abs(c['change_percentage']), 
                              reverse=True)
    
    # Apply optional pagination
    try:
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 50))
        start = (page - 1) * page_size
        end = start + page_size
        paginated_changes = metric_changes[start:end]
    except ValueError:
        paginated_changes = metric_changes
    
    return jsonify({
        "comparison_id": comparison_id,
        "total_count": len(metric_changes),
        "metric_changes": paginated_changes
    })

@comparison_bp.route('/comparison/<comparison_id>/function/<function_id>', methods=['GET'])
@login_required
def get_comparison_function_detail(comparison_id, function_id):
    """Get detailed comparison of a specific function."""
    comparison = store.get_comparison(comparison_id)
    if not comparison:
        return jsonify({"error": f"Comparison {comparison_id} not found"}), 404
    
    # Find the function change entry
    corresponding_id = None
    change_type = None
    
    if comparison.function_changes:
        if function_id in comparison.function_changes:
            change_type, corresponding_id = comparison.function_changes[function_id]
    
    if not change_type:
        return jsonify({"error": f"Function {function_id} not found in comparison"}), 404
    
    # Get function details
    base_function = None
    target_function = None
    
    # Get base function from project1
    if change_type in [ChangeType.REMOVED, ChangeType.MODIFIED, ChangeType.RENAMED, ChangeType.UNCHANGED]:
        project1 = store.get_project(comparison.project1_id)
        if project1:
            for func in project1.analysis_data.get('functions', []):
                if func.get('id') == function_id:
                    base_function = func
                    break
    
    # Get target function from project2
    if change_type in [ChangeType.ADDED, ChangeType.MODIFIED, ChangeType.RENAMED, ChangeType.UNCHANGED]:
        if corresponding_id:
            project2 = store.get_project(comparison.project2_id)
            if project2:
                for func in project2.analysis_data.get('functions', []):
                    if func.get('id') == corresponding_id:
                        target_function = func
                        break
    
    # Get call graph changes
    call_changes = []
    for change in comparison.call_graph_changes:
        if change["caller_id"] == function_id:
            call_changes.append(change)
    
    # Get performance metric changes
    metric_changes = {}
    if function_id in comparison.metric_changes:
        metric_changes = comparison.metric_changes[function_id]
    
    return jsonify({
        "comparison_id": comparison_id,
        "function_id": function_id,
        "corresponding_id": corresponding_id,
        "change_type": change_type.name if change_type else None,
        "base_function": base_function,
        "target_function": target_function,
        "call_changes": call_changes,
        "metric_changes": metric_changes
    })

@comparison_bp.route('/compare', methods=['POST'])
@login_required
def create_comparison():
    """Create a new comparison between two projects."""
    data = request.json
    
    # Check required fields
    if not data.get('project1_id') or not data.get('project2_id'):
        return jsonify({"error": "Both project1_id and project2_id are required"}), 400
    
    # Get projects
    project1 = store.get_project(data['project1_id'])
    project2 = store.get_project(data['project2_id'])
    
    if not project1:
        return jsonify({"error": f"Project {data['project1_id']} not found"}), 404
    if not project2:
        return jsonify({"error": f"Project {data['project2_id']} not found"}), 404
    
    try:
        # Create analysis versions from the projects
        base_version = AnalysisVersion(
            project_id=project1.id,
            version_name=project1.version,
            binary_path=project1.binary_path,
            description=project1.description,
            metadata={"timestamp": project1.timestamp.isoformat() if project1.timestamp else ""},
        )
        
        target_version = AnalysisVersion(
            project_id=project2.id,
            version_name=project2.version,
            binary_path=project2.binary_path,
            description=project2.description,
            metadata={"timestamp": project2.timestamp.isoformat() if project2.timestamp else ""},
        )
        
        # Convert project analysis_data to functions and structures
        _convert_project_to_version(project1.analysis_data, base_version)
        _convert_project_to_version(project2.analysis_data, target_version)
        
        # Initialize comparator
        name_threshold = data.get('name_similarity_threshold', 0.85)
        code_threshold = data.get('code_similarity_threshold', 0.75)
        comparator = BinaryComparator(
            name_similarity_threshold=name_threshold,
            code_similarity_threshold=code_threshold
        )
        
        # Perform comparison
        result = comparator.compare(base_version, target_version)
        
        # Convert to serializable format
        result_data = result.to_dict()
        
        # Create comparison result
        comparison = ComparisonResult(
            base_version_id=base_version.version_id,
            target_version_id=target_version.version_id,
            base_version_name=project1.name,
            target_version_name=project2.name,
        )
        
        # Set similarity scores
        comparison.set_similarity_scores(
            result.overall_similarity,
            result.function_similarity,
            result.structure_similarity,
            result.call_graph_similarity
        )
        
        # Add function changes
        for func_id, (change_type, target_id) in result.function_changes.items():
            # Only add if it's in base_version (target-only functions are handled separately)
            if func_id in base_version.functions:
                comparison.add_function_change(func_id, change_type, target_id)
        
        # Add structure changes
        for struct_id, (change_type, target_id) in result.structure_changes.items():
            # Only add if it's in base_version (target-only structures are handled separately)
            if struct_id in base_version.structures:
                comparison.add_structure_change(struct_id, change_type, target_id)
        
        # Add call graph changes
        for change in result.call_graph_changes:
            comparison.add_call_graph_change(
                change["caller_id"],
                change["callee_id"],
                ChangeType[change["change_type"]]
            )
        
        # Add performance metric changes
        for func_id, metrics in result.metric_changes.items():
            for metric_name, values in metrics.items():
                comparison.add_metric_change(
                    func_id,
                    metric_name,
                    values["base_value"],
                    values["target_value"],
                    values["change_percentage"]
                )
        
        # Create comparison for storage
        storage_comparison = ComparisonResult(
            base_version_id=result.base_version_id,
            target_version_id=result.target_version_id,
            base_version_name=result.base_version_name,
            target_version_name=result.target_version_name
        )
        
        # Optional fields from request
        if 'name' in data:
            storage_comparison.name = data['name']
        else:
            storage_comparison.name = f"Comparison of {project1.name} and {project2.name}"
            
        if 'description' in data:
            storage_comparison.description = data['description']
        else:
            storage_comparison.description = f"Comparing {project1.name} ({project1.version}) with {project2.name} ({project2.version})"
            
        if 'tags' in data:
            storage_comparison.tags = data['tags']
            
        # Save the serialized result
        comparison_id = store.save_comparison(storage_comparison)
        
        return jsonify({
            "id": comparison_id,
            "message": "Comparison created successfully",
            "comparison": result_data
        })
    except Exception as e:
        return jsonify({"error": f"Comparison failed: {str(e)}"}), 500


def _convert_project_to_version(analysis_data, version):
    """Convert project analysis data to AnalysisVersion format."""
    # Add functions
    if 'functions' in analysis_data:
        for func_data in analysis_data['functions']:
            function = FunctionInfo(
                name=func_data.get('name', 'Unknown'),
                address=func_data.get('address', 0),
                size=func_data.get('size', 0),
                signature=func_data.get('signature'),
                function_id=func_data.get('id'),
                complexity=func_data.get('complexity'),
                decompiled_code=func_data.get('decompiled_code'),
                summary=func_data.get('summary'),
                tags=func_data.get('tags', [])
            )
            
            # Add parameters if available
            if 'parameters' in func_data:
                for i, param in enumerate(func_data['parameters']):
                    param_info = ParameterInfo(
                        name=param.get('name', f'param{i}'),
                        type_name=param.get('type', 'unknown'),
                        position=i,
                        size=param.get('size', 0)
                    )
                    function.add_parameter(param_info)
            
            # Add local variables if available
            if 'local_vars' in func_data:
                for var in func_data['local_vars']:
                    var_info = VariableInfo(
                        name=var.get('name', 'var'),
                        type_name=var.get('type', 'unknown'),
                        size=var.get('size', 0),
                        is_stack=var.get('is_stack', True)
                    )
                    function.add_local_var(var_info)
            
            version.add_function(function)
    
    # Add structures
    if 'structures' in analysis_data:
        for struct_data in analysis_data['structures']:
            structure = StructureInfo(
                name=struct_data.get('name', 'Unknown'),
                size=struct_data.get('size', 0),
                structure_id=struct_data.get('id'),
                is_union=struct_data.get('is_union', False)
            )
            
            # Add fields if available
            if 'fields' in struct_data:
                for field in struct_data['fields']:
                    field_info = StructureField(
                        name=field.get('name', 'field'),
                        type_name=field.get('type', 'unknown'),
                        offset=field.get('offset', 0),
                        size=field.get('size', 0)
                    )
                    structure.add_field(field_info)
            
            version.add_structure(structure)
    
    # Add call graph
    if 'call_graph' in analysis_data:
        for caller, callees in analysis_data['call_graph'].items():
            for callee in callees:
                version.add_call(caller, callee)
    
    # Add performance metrics
    if 'performance_metrics' in analysis_data:
        for func_id, metrics in analysis_data['performance_metrics'].items():
            version.set_performance_metrics(func_id, metrics)

@comparison_bp.route('/comparison/<comparison_id>', methods=['DELETE'])
@login_required
def delete_comparison(comparison_id):
    """Delete a comparison."""
    success = store.delete_comparison(comparison_id)
    if not success:
        return jsonify({"error": f"Comparison {comparison_id} not found"}), 404
    
    return jsonify({"message": f"Comparison {comparison_id} deleted successfully"})

@comparison_bp.route('/analysis/export/<project_id>', methods=['GET'])
@login_required
def export_analysis(project_id):
    """Export an analysis project as a JSON file."""
    project = store.get_project(project_id)
    if not project:
        return jsonify({"error": f"Project {project_id} not found"}), 404
    
    # Create temporary file
    import tempfile
    
    fd, temp_path = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    
    # Write project data to file
    with open(temp_path, 'w') as f:
        json.dump({
            "id": project.id,
            "name": project.name,
            "binary_path": project.binary_path,
            "timestamp": project.timestamp.isoformat() if project.timestamp else None,
            "version": project.version,
            "description": project.description,
            "tags": project.tags,
            "analysis_data": project.analysis_data
        }, f, indent=2)
    
    # Send file
    return send_file(
        temp_path,
        as_attachment=True,
        download_name=f"{project.name.replace(' ', '_')}_analysis.json",
        mimetype='application/json'
    )

@comparison_bp.route('/analysis/import', methods=['POST'])
@login_required
def import_analysis():
    """Import an analysis project from a JSON file."""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400
    
    # Check file extension
    if not file.filename.endswith('.json'):
        return jsonify({"error": "File must be a JSON file"}), 400
    
    # Load file content
    try:
        data = json.load(file)
        
        # Create project
        project = AnalysisProject(
            name=data['name'],
            description=data.get('description', ''),
            binary_path=data.get('binary_path', '')
        )
        
        # Add optional fields
        if 'timestamp' in data:
            try:
                project.timestamp = datetime.fromisoformat(data['timestamp'])
            except ValueError:
                pass
        if 'version' in data:
            project.version = data['version']
        if 'description' in data:
            project.description = data['description']
        if 'tags' in data:
            project.tags = data['tags']
        
        # Save project
        project_id = store.save_project(project)
        
        return jsonify({
            "id": project_id,
            "message": "Analysis imported successfully"
        })
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON file"}), 400
    except KeyError as e:
        return jsonify({"error": f"Missing required field: {str(e)}"}), 400