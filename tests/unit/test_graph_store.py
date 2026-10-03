"""Unit tests for GraphStore and Knowledge Graph construction."""

from guardianos.graph.builder import populate_graph_from_ingestion
from guardianos.graph.networkx_store import NetworkXGraphStore
from guardianos.inventory.parser import parse_sbom


def test_networkx_graph_store_basic():
    store = NetworkXGraphStore()
    store.add_node("app:1", "Application", {"name": "Discourse"})
    store.add_node("pkg:1", "Package", {"name": "ImageMagick"})
    store.add_node("lib:1", "Library", {"name": "libheif"})

    store.add_edge("app:1", "pkg:1", "DEPENDS_ON")
    store.add_edge("pkg:1", "lib:1", "CONTAINS")

    # Verify node retrieval
    node = store.get_node("app:1")
    assert node is not None
    assert node.label == "Application"
    assert node.properties["name"] == "Discourse"

    # Verify paths discovery
    paths = store.find_paths("app:1", "lib:1")
    assert len(paths) == 1
    assert paths[0][0]["node_id"] == "app:1"
    assert paths[0][1]["node_id"] == "pkg:1"
    assert paths[0][2]["node_id"] == "lib:1"


def test_populate_graph_from_ingestion(sample_cyclonedx_json):
    store = NetworkXGraphStore()
    result = parse_sbom(sample_cyclonedx_json, application="demo-app")
    
    nodes_added = populate_graph_from_ingestion(result, store=store)
    assert nodes_added == 4

    # Verify subgraph from root application
    root_purl = "pkg:generic/image-processing-service@2.4.0"
    subgraph = store.get_subgraph(root_purl, max_depth=3)
    assert len(subgraph.nodes) == 4
    assert len(subgraph.edges) == 3
