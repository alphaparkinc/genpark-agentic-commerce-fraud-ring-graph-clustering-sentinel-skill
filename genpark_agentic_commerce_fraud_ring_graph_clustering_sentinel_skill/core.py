# -*- coding: utf-8 -*-
"""Commerce Fraud Ring Graph Louvain Clustering Sentinel for GenPark Agentic Commerce."""
import json
import hashlib
import time
from typing import Dict, Any, List

class FraudRingGraphClusteringSentinel:
    """Real-time transaction entity graph clustering and fraud ring detection engine."""

    @staticmethod
    def analyze_transaction_graph_cluster(transactions: List[Dict[str, Any]], cluster_similarity_threshold: float = 0.5) -> Dict[str, Any]:
        """Group transactions by shared entity ties (device, IP subnet, card BIN)."""
        nodes = len(transactions)
        edges = []
        clusters = {}
        cluster_counter = 1

        # Build pairwise adjacency
        for i in range(nodes):
            t1 = transactions[i]
            for j in range(i + 1, nodes):
                t2 = transactions[j]
                shared_score = 0.0
                shared_reasons = []

                if t1.get("device_fingerprint") == t2.get("device_fingerprint") and t1.get("device_fingerprint"):
                    shared_score += 0.50
                    shared_reasons.append("identical_device_hash")
                if t1.get("ip_subnet") == t2.get("ip_subnet") and t1.get("ip_subnet"):
                    shared_score += 0.25
                    shared_reasons.append("common_ip_subnet")
                if t1.get("card_bin") == t2.get("card_bin") and t1.get("card_bin"):
                    shared_score += 0.20
                    shared_reasons.append("same_issuing_bin")

                if shared_score >= cluster_similarity_threshold:
                    edges.append({
                        "source": t1["tx_id"],
                        "target": t2["tx_id"],
                        "score": round(shared_score, 2),
                        "signals": shared_reasons
                    })

        # Simple connected components grouping
        parent = {t["tx_id"]: t["tx_id"] for t in transactions}
        def find(u):
            if parent[u] != u:
                parent[u] = find(parent[u])
            return parent[u]
        def union(u, v):
            root_u, root_v = find(u), find(v)
            if root_u != root_v:
                parent[root_v] = root_u

        for edge in edges:
            union(edge["source"], edge["target"])

        group_map = {}
        for t in transactions:
            r = find(t["tx_id"])
            if r not in group_map:
                group_map[r] = []
            group_map[r].append(t)

        detected_fraud_rings = []
        isolated_tx_count = 0
        total_ring_exposure = 0.0

        for r, txs in group_map.items():
            if len(txs) > 1:
                ring_exposure = sum(t.get("amount_usd", 0.0) for t in txs)
                total_ring_exposure += ring_exposure
                detected_fraud_rings.append({
                    "ring_id": f"RING-{hashlib.sha256(r.encode()).hexdigest()[:8]}",
                    "member_tx_count": len(txs),
                    "unique_users": len(set(t.get("user_id") for t in txs)),
                    "total_amount_usd": round(ring_exposure, 2),
                    "tx_ids": [t["tx_id"] for t in txs],
                    "risk_level": "CRITICAL_SYNDICATE" if len(txs) >= 4 else "HIGH_RISK_COLLUSION"
                })
            else:
                isolated_tx_count += 1

        return {
            "total_transactions_evaluated": nodes,
            "connected_edge_count": len(edges),
            "isolated_clean_transactions": isolated_tx_count,
            "detected_fraud_rings_count": len(detected_fraud_rings),
            "total_fraud_ring_exposure_usd": round(total_ring_exposure, 2),
            "fraud_rings": detected_fraud_rings
        }

    @staticmethod
    def compile_fraud_ring_interdiction_dossier(cluster_id: str, member_tx_ids: List[str], total_exposure_usd: float, primary_vector: str) -> Dict[str, Any]:
        """Compile formal merchant risk interdiction package and 3DS gateway rule."""
        dossier_id = f"DOSSIER-{int(time.time())}-{cluster_id}"
        return {
            "dossier_id": dossier_id,
            "cluster_id": cluster_id,
            "impacted_transactions_count": len(member_tx_ids),
            "total_exposure_usd": round(total_exposure_usd, 2),
            "primary_attack_vector": primary_vector,
            "recommended_actions": [
                "Execute instant pre-auth capture freeze on all member transaction IDs.",
                "Enforce mandatory step-up FIDO2 / Passkey biometric 3D Secure challenge on device fingerprint.",
                "Append IP CIDR subnet and device fingerprint to merchant edge firewall drop list.",
                "Export cryptographic transaction lineage report for Visa/Mastercard dispute arbitration."
            ],
            "gateway_action": "REJECT_AND_FLAG"
        }
