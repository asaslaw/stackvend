"""
Project Castor: Developer Agent Structured IaC Schemas
Pydantic specifications for schema-constrained generation of services and supplemental resources.
"""

from typing import Any, Dict, List, Optional
try:
    from pydantic import BaseModel, Field
except ImportError:
    # Graceful fallback if pydantic is mocked in testing environments
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self):
            return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
    def Field(default=None, default_factory=None, **kwargs):  # type: ignore
        return default_factory() if default_factory else default


class AdditionalServiceSpec(BaseModel):
    name: str = Field(..., description="Service identifier, e.g. 'red', 'frontend', 'worker'")
    relative_path: str = Field(..., description="Relative app directory, e.g. 'apps/red'")
    allow_unauthenticated: bool = Field(default=False, description="Whether public access is permitted")
    enable_direct_iap: bool = Field(default=True, description="Whether Direct IAP is enabled")
    authorized_invoker_members: List[str] = Field(default_factory=list, description="IAM members permitted through IAP")
    cpu_limit: str = Field(default="1000m", description="Container CPU limit")
    memory_limit: str = Field(default="512Mi", description="Container memory limit")


class StorageBucketSpec(BaseModel):
    name_suffix: str = Field(default="data", description="Suffix for bucket name, e.g. 'documents', 'uploads'")
    versioning_enabled: bool = Field(default=False, description="Enable object versioning")
    lifecycle_delete_days: Optional[int] = Field(default=None, description="Auto-delete objects older than N days")


class PubSubTopicSpec(BaseModel):
    topic_name: str = Field(..., description="Pub/Sub topic name")
    enable_dead_letter: bool = Field(default=True, description="Attach a dead letter queue")
    ack_deadline_seconds: int = Field(default=60, description="Acknowledgment deadline in seconds")


class WorkloadIaCSpec(BaseModel):
    compute_archetype: str = Field(default="cloudrun", description="cloudrun, gke-autopilot, gce-bastion, event-worker, foundation-only")
    additional_services: List[AdditionalServiceSpec] = Field(default_factory=list, description="Secondary services in multi-service workloads")
    storage_buckets: List[StorageBucketSpec] = Field(default_factory=list, description="Requested GCS buckets")
    pubsub_topics: List[PubSubTopicSpec] = Field(default_factory=list, description="Requested Pub/Sub topics")


def parse_iac_spec(data: Any) -> WorkloadIaCSpec:
    """Safely converts dict or JSON-like structure into a WorkloadIaCSpec."""
    if isinstance(data, WorkloadIaCSpec):
        return data
    if not isinstance(data, dict):
        return WorkloadIaCSpec()

    add_svcs = []
    for s in data.get("additional_services", []):
        if isinstance(s, dict) and "name" in s and "relative_path" in s:
            add_svcs.append(AdditionalServiceSpec(
                name=s["name"],
                relative_path=s["relative_path"],
                allow_unauthenticated=s.get("allow_unauthenticated", False),
                enable_direct_iap=s.get("enable_direct_iap", True),
                authorized_invoker_members=s.get("authorized_invoker_members", []),
                cpu_limit=s.get("cpu_limit", "1000m"),
                memory_limit=s.get("memory_limit", "512Mi"),
            ))

    buckets = []
    for b in data.get("storage_buckets", []):
        if isinstance(b, dict):
            buckets.append(StorageBucketSpec(
                name_suffix=b.get("name_suffix", "data"),
                versioning_enabled=b.get("versioning_enabled", False),
                lifecycle_delete_days=b.get("lifecycle_delete_days"),
            ))
        elif isinstance(b, str):
            buckets.append(StorageBucketSpec(name_suffix=b))

    topics = []
    for t in data.get("pubsub_topics", []):
        if isinstance(t, dict) and "topic_name" in t:
            topics.append(PubSubTopicSpec(
                topic_name=t["topic_name"],
                enable_dead_letter=t.get("enable_dead_letter", True),
                ack_deadline_seconds=t.get("ack_deadline_seconds", 60),
            ))
        elif isinstance(t, str):
            topics.append(PubSubTopicSpec(topic_name=t))

    return WorkloadIaCSpec(
        compute_archetype=data.get("compute_archetype", "cloudrun"),
        additional_services=add_svcs,
        storage_buckets=buckets,
        pubsub_topics=topics,
    )
