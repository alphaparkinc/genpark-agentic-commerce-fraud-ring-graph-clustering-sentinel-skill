# -*- coding: utf-8 -*-
"""MCP Server for Commerce Fraud Ring Graph Louvain Clustering Sentinel Skill."""
import sys
import json
import logging
from typing import Dict, Any

from .core import FraudRingGraphClusteringSentinel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TOOLS_SCHEMA = [
    {
        "name": "analyze_transaction_graph_cluster",
        "description": "Analyze multi-attribute transaction entity graph for connected syndication clusters and high-risk coordinated fraud patterns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "transactions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "tx_id": {
                                "type": "string"
                            },
                            "user_id": {
                                "type": "string"
                            },
                            "amount_usd": {
                                "type": "number"
                            },
                            "device_fingerprint": {
                                "type": "string"
                            },
                            "ip_subnet": {
                                "type": "string"
                            },
                            "card_bin": {
                                "type": "string"
                            }
                        },
                        "required": [
                            "tx_id",
                            "user_id",
                            "amount_usd",
                            "device_fingerprint",
                            "ip_subnet"
                        ]
                    }
                },
                "cluster_similarity_threshold": {
                    "type": "number"
                }
            },
            "required": [
                "transactions"
            ]
        }
    },
    {
        "name": "compile_fraud_ring_interdiction_dossier",
        "description": "Compile an interdiction dossier detailing high-risk cluster nodes, recommended payment gateway blocks, and 3DS challenge rules.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cluster_id": {
                    "type": "string"
                },
                "member_tx_ids": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "total_exposure_usd": {
                    "type": "number"
                },
                "primary_vector": {
                    "type": "string"
                }
            },
            "required": [
                "cluster_id",
                "member_tx_ids",
                "total_exposure_usd",
                "primary_vector"
            ]
        }
    }
]

def handle_rpc(line: str) -> str:
    try:
        req = json.loads(line)
        method = req.get("method")
        msg_id = req.get("id")

        if method == "initialize":
            res = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "genpark-agentic-commerce-fraud-ring-graph-clustering-sentinel-skill", "version": "1.0.0"}
            }
            return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": res})

        elif method == "tools/list":
            return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS_SCHEMA}})

        elif method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name")
            args = params.get("arguments", {})

            target_func = getattr(FraudRingGraphClusteringSentinel, tool_name, None)
            if not target_func:
                return json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {tool_name}"}})

            result = target_func(**args)
            return json.dumps({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}]
                }
            })

        else:
            return json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}})

    except Exception as e:
        return json.dumps({"jsonrpc": "2.0", "id": req.get("id") if "req" in locals() else None, "error": {"code": -32000, "message": str(e)}})

def run_test():
    print("[TEST] Running internal RPC self-test for genpark-agentic-commerce-fraud-ring-graph-clustering-sentinel-skill...")
    init_req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    init_res = json.loads(handle_rpc(init_req))
    assert init_res.get("result", {}).get("serverInfo", {}).get("name") == "genpark-agentic-commerce-fraud-ring-graph-clustering-sentinel-skill"

    list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    list_res = json.loads(handle_rpc(list_req))
    assert len(list_res.get("result", {}).get("tools", [])) == 2
    print(f"[TEST] SUCCESS: {len(list_res['result']['tools'])} tools verified.")
    return True

if __name__ == "__main__":
    if "--test" in sys.argv:
        if run_test():
            sys.exit(0)
        sys.exit(1)

    for line in sys.stdin:
        if not line.strip():
            continue
        out = handle_rpc(line)
        sys.stdout.write(out + "\n")
        sys.stdout.flush()
