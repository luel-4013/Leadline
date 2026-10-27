"""
Leadline - Graph Builder Phase
Phase 9: NetworkX-based attack surface graph construction
"""
import networkx as nx
from typing import Dict, Any, List, Set
from urllib.parse import urlparse
from app.recon.base import BaseReconPhase


class GraphBuilderPhase(BaseReconPhase):
    """Graph Builder reconnaissance phase."""

    name = "graph_builder"
    order = 12
    description = "NetworkX-based attack surface graph construction"

    async def execute(self) -> Dict[str, Any]:
        """Execute graph building using NetworkX."""
        try:
            # Create a directed graph
            G = nx.DiGraph()

            nodes: List[Dict[str, Any]] = []
            edges: List[Dict[str, Any]] = []

            root_node = "/"

            # Add root node
            G.add_node(root_node, type="root", label="/", depth=0)

            # Collect all discovered endpoints from previous phases
            all_paths: Set[str] = set()

            # From HTTP fingerprinting
            http_results = self.context.get('http_fingerprinting', {})
            detailed_results = http_results.get('detailed_results', {})
            for method, result in detailed_results.items():
                if isinstance(result, dict) and 'final_url' in result:
                    final_url = result['final_url']
                    try:
                        path = urlparse(final_url).path
                        if path:
                            all_paths.add(path)
                    except Exception:
                        pass

            # From JS analysis
            js_results = self.context.get('js_analysis', {})
            js_endpoints = js_results.get('extracted_endpoints', [])
            for endpoint in js_endpoints:
                try:
                    path = urlparse(endpoint).path
                    if path:
                        all_paths.add(path)
                except Exception:
                    pass

            # From API discovery
            api_results = self.context.get('api_discovery', {})
            api_endpoints = api_results.get('api_endpoints', [])
            for endpoint in api_endpoints:
                url = endpoint.get('url', '')
                try:
                    path = urlparse(url).path
                    if path:
                        all_paths.add(path)
                except Exception:
                    pass

            # From parameter discovery
            param_results = self.context.get('param_discovery', {})
            url_parameters = param_results.get('url_parameters', [])
            for param in url_parameters:
                location = param.get('location', '')
                if location and location.startswith('/'):
                    all_paths.add(location)

            # Normalize paths and build hierarchy
            normalized_paths = self._normalize_paths(all_paths)

            # Build tree structure
            path_tree = {}
            for path in normalized_paths:
                parts = [p for p in path.split('/') if p]
                current = path_tree
                for i, part in enumerate(parts):
                    if part not in current:
                        current[part] = {}
                    current = current[part]

            # Add nodes and edges to graph
            added_nodes: Set[str] = {root_node}

            for path in normalized_paths:
                parts = [p for p in path.split('/') if p]
                parent_path = "/"

                for i, part in enumerate(parts):
                    current_path = "/" + "/".join(parts[:i+1])

                    # Determine node type
                    node_type = "endpoint"
                    if '/api/' in current_path:
                        node_type = "api"
                    elif '/admin' in current_path:
                        node_type = "admin"
                    elif '/debug' in current_path:
                        node_type = "debug"
                    elif current_path.endswith('.js'):
                        node_type = "javascript"
                    elif any(current_path.endswith(ext) for ext in ['.css', '.png', '.jpg', '.gif', '.svg']):
                        node_type = "static"

                    # Add node if not exists
                    if current_path not in added_nodes:
                        G.add_node(current_path, type=node_type, label=f"/{part}", depth=i+1)
                        added_nodes.add(current_path)

                        nodes.append({
                            "id": current_path,
                            "type": node_type,
                            "label": f"/{part}",
                            "depth": i + 1
                        })

                    # Add edge from parent
                    if parent_path != current_path and parent_path in added_nodes:
                        if not G.has_edge(parent_path, current_path):
                            G.add_edge(parent_path, current_path, relationship="contains")
                            edges.append({
                                "source": parent_path,
                                "target": current_path,
                                "relationship": "contains"
                            })

                    parent_path = current_path

            # Calculate graph statistics
            num_nodes = G.number_of_nodes()
            num_edges = G.number_of_edges()

            # Convert to tree structure for frontend
            tree_structure = self._build_tree_dict(path_tree)

            return {
                "nodes": nodes,
                "node_count": num_nodes,
                "edges": edges,
                "edge_count": num_edges,
                "tree_structure": tree_structure,
                "has_cycles": not nx.is_directed_acyclic_graph(G) if num_nodes > 0 else False,
                "status": "completed"
            }

        except ImportError:
            # Fallback without NetworkX
            return self._build_simple_graph()
        except Exception as e:
            return {
                "nodes": [],
                "edges": [],
                "tree_structure": {},
                "status": "failed",
                "error": str(e)
            }

    def _normalize_paths(self, paths: Set[str]) -> List[str]:
        """Normalize and sort paths for consistent tree building."""
        normalized = []
        for path in paths:
            # Clean up the path
            clean_path = path.split('?')[0]  # Remove query params
            if clean_path and clean_path != '/':
                normalized.append(clean_path)

        # Sort by depth (shorter paths first)
        normalized.sort(key=lambda p: (p.count('/'), p))
        return normalized

    def _build_tree_dict(self, tree: Dict) -> Dict[str, Any]:
        """Build a nested dictionary representing the path tree."""
        result = {"children": {}, "type": "root", "label": "/"}

        def build_node(subtree: Dict, parent: Dict):
            for key, value in subtree.items():
                node_type = "endpoint"
                if '/api/' in key or key.startswith('api'):
                    node_type = "api"
                elif key == 'admin':
                    node_type = "admin"
                elif key == 'debug':
                    node_type = "debug"
                elif key.endswith('.js'):
                    node_type = "javascript"

                child = {
                    "label": f"/{key}",
                    "type": node_type,
                    "children": {}
                }
                parent["children"][key] = child

                if value:
                    build_node(value, child)

        build_node(tree, result)
        return result

    def _build_simple_graph(self) -> Dict[str, Any]:
        """Fallback graph building without NetworkX."""
        nodes = []
        edges = []

        # Add root
        nodes.append({"id": "/", "type": "root", "label": "/", "depth": 0})

        # Collect paths from context
        all_paths: Set[str] = set()

        api_results = self.context.get('api_discovery', {})
        for endpoint in api_results.get('api_endpoints', []):
            url = endpoint.get('url', '')
            try:
                path = urlparse(url).path
                if path:
                    all_paths.add(path)
            except Exception:
                pass

        for path in all_paths:
            if path and path != '/':
                nodes.append({
                    "id": path,
                    "type": "endpoint",
                    "label": path.split('/')[-1] or path,
                    "depth": 1
                })
                edges.append({
                    "source": "/",
                    "target": path,
                    "relationship": "contains"
                })

        return {
            "nodes": nodes,
            "node_count": len(nodes),
            "edges": edges,
            "edge_count": len(edges),
            "tree_structure": {"children": {}, "type": "root", "label": "/"},
            "status": "completed"
        }
