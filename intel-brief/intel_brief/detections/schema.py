"""Structured-output schema for AI-drafted Sigma rules.

The model fills in fields; sigma_build.py turns them into YAML. The model never
writes raw YAML, so it can't smuggle in extra keys, anchors or tags.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Modifier = Literal[
    "contains", "startswith", "endswith", "all", "re", "cidr", "windash", "base64offset", "wide"
]

Category = Literal[
    "process_creation", "network_connection", "file_event", "file_access", "file_delete",
    "registry_set", "registry_add", "registry_event", "image_load", "dns_query", "pipe_created",
    "ps_script", "ps_module", "driver_load", "create_remote_thread", "process_access",
    "webserver", "proxy", "firewall", "antivirus", "none",
]

Product = Literal["windows", "linux", "macos", "azure", "m365", "okta", "aws", "gcp", "none"]


class FieldCondition(BaseModel):
    field: str = Field(description="Sigma taxonomy field name, e.g. Image, CommandLine, ParentImage, TargetFilename, DestinationPort.")
    modifiers: list[Modifier] = Field(description="Value modifiers in order; empty for exact match.")
    values: list[str] = Field(description="One or more values; any one matching satisfies the condition unless 'all' is set.")


class Selection(BaseModel):
    name: str = Field(description="selection_<word> or filter_<word>, lowercase letters, digits, underscores.")
    conditions: list[FieldCondition] = Field(description="All conditions in one selection must match (AND).")


class SigmaRuleDraft(BaseModel):
    title: str = Field(description="Short rule title, at most 100 characters.")
    description: str = Field(description="What the rule detects and why, 1-3 sentences.")
    logsource_product: Product
    logsource_category: Category
    logsource_service: str = Field(description="Sigma service (e.g. security, sysmon, audit) or empty.")
    selections: list[Selection] = Field(description="Named selections and filters.")
    condition: str = Field(description="Sigma condition using only the selection names, and/or/not, parentheses, '1 of selection_*', 'all of selection_*'.")
    falsepositives: list[str]
    level: Literal["informational", "low", "medium", "high", "critical"]
    attack_tags: list[str] = Field(description="MITRE ATT&CK tags such as attack.execution or attack.t1059.001.")
