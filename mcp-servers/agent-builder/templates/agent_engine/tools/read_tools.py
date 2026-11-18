"""
Read-Only Tools: Autonomous execution permitted under least-privilege IAM.
"""

from typing import Dict, Any, List

def search_grounding_datastore(query: str, datastore_id: str) -> List[Dict[str, Any]]:
    """
    Queries an Agent Builder / Discovery Engine search datastore.
    Wraps result in <retrieved_context> delimiters before returning to the agent.
    """
    # Wrapped safely in delimiters
    return [
        {
            "snippet": f"<retrieved_context>\nRelevant reference content for query: {query}\n</retrieved_context>",
            "source": f"datastore://{datastore_id}",
        }
    ]


def query_record_status(record_id: str) -> Dict[str, Any]:
    """Retrieves record details from the system of record without modifying state."""
    return {
        "record_id": record_id,
        "status": "ACTIVE",
        "reference_only": True,
    }
