"""Closed Daimon instance manifests and explainable task selection.

The prose definition is identity/philosophy, not executable authorization.
Selectors consume only reviewed structured fields and always leave action
authorization to the referenced policy plane.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse


MANIFEST_SCHEMA = "daimon-manifest/v1"
TASK_SCHEMA = "daimon-task-requirements/v1"
DECISION_SCHEMA = "daimon-selector-decision/v1"
INVENTORY_SCHEMA = "daimon-concept-inventory/v1"
CLASSIFICATIONS = {"public", "tribe-shared", "internal", "private"}
MATURITY = {"implemented", "partial", "aspirational"}
AUTHORITY = {"source", "retrieval-index", "downstream", "projection"}
MEMORY_ROLES = {
    "operational-private",
    "knowledge-source",
    "downstream-publication",
    "navigation-projection",
}
COMMUNICATION_SCOPES = {
    "direct",
    "human",
    "tribe",
    "everyone",
    "here",
    "near",
    "all",
}
REFERENCE_SCHEMES = {"env", "secret-store"}
ENDPOINT_SCHEMES = {
    "hmk",
    "file-source",
    "collective",
    "projection",
    "tribe",
    "github",
    "human",
    "local",
}

_TOP_KEYS = {
    "schema",
    "manifest_id",
    "subject",
    "definition",
    "lineage",
    "provenance",
    "portability",
    "trust_domains",
    "embodiment",
    "memory_endpoints",
    "communication_endpoints",
    "capabilities",
    "secret_refs",
    "governance",
}
_DEFINITION_KEYS = {"source_uri", "source_sha256", "species_sha256"}
_LINEAGE_KEYS = {"species_id", "definition_sha256"}
_PROVENANCE_KEYS = {
    "generated_at",
    "generator",
    "source_repository",
    "source_commit",
}
_PORTABILITY_KEYS = {
    "generation_scheme",
    "generation_id",
    "source_commit",
    "artifact_index_sha256",
    "restore_contract",
}
_TRUST_KEYS = {"id", "classifications", "endpoint_schemes", "policy_refs"}
_EMBODIMENT_KEYS = {
    "realm",
    "body_id",
    "surfaces",
    "sensors",
    "actuators",
    "tools",
}
_MEMORY_KEYS = {
    "id",
    "role",
    "authority",
    "uri",
    "modes",
    "classifications",
    "trust_domain",
    "policy_refs",
}
_COMMUNICATION_KEYS = {
    "id",
    "scope",
    "uri",
    "modes",
    "classifications",
    "trust_domain",
    "policy_refs",
}
_CAPABILITY_KEYS = {
    "id",
    "kind",
    "maturity",
    "version",
    "interfaces",
    "task_labels",
    "trust_domains",
    "evidence",
    "constraints",
}
_EVIDENCE_KEYS = {"uri", "sha256"}
_SECRET_REF_KEYS = {"name", "reference"}
_GOVERNANCE_KEYS = {
    "owner",
    "decision_refs",
    "authorization_policy_refs",
}
_TASK_KEYS = {
    "schema",
    "task_id",
    "required_capabilities",
    "required_tools",
    "required_classification",
    "required_trust_domains",
    "required_realm",
    "allow_partial",
}
_INVENTORY_KEYS = {"schema", "source", "governance_owner", "concepts"}
_INVENTORY_SOURCE_KEYS = {
    "uri",
    "observed_at",
    "source_last_edited",
    "sha256",
}
_CONCEPT_KEYS = {
    "id",
    "source_expression",
    "classification",
    "executable_mapping",
    "status_date",
    "notes",
}
_ID = re.compile(r"[a-z0-9][a-z0-9._@/-]{1,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP)? ?PRIVATE KEY-----"),
    re.compile(r"\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.I),
)


class DaimonManifestError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def manifest_sha256(manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def _closed(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise DaimonManifestError(f"{label} has unknown or missing fields")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DaimonManifestError(f"{label} must be a non-empty string")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _string(value, label)
    if not _ID.fullmatch(text):
        raise DaimonManifestError(f"{label} is not a safe identifier")
    return text


def _unique_strings(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise DaimonManifestError(f"{label} must contain unique strings")
    return value


def _hash(value: Any, label: str) -> str:
    text = _string(value, label)
    if not _SHA256.fullmatch(text):
        raise DaimonManifestError(f"{label} must be lowercase SHA-256")
    return text


def _uri(value: Any, label: str, schemes: set[str] | None = None) -> str:
    text = _string(value, label)
    parsed = urlparse(text)
    if not parsed.scheme or (schemes is not None and parsed.scheme not in schemes):
        raise DaimonManifestError(f"{label} uses an unsupported URI scheme")
    return text


def _refs(value: Any, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise DaimonManifestError(f"{label} must be a list")
    result = []
    for item in value:
        entry = _closed(item, _EVIDENCE_KEYS, label)
        result.append(
            {
                "uri": _uri(entry["uri"], f"{label}.uri"),
                "sha256": _hash(entry["sha256"], f"{label}.sha256"),
            }
        )
    return result


def _reject_embedded_secrets(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key not in {"secret_refs", "reference"} and re.search(
                r"(?:password|token|private[_-]?key|client[_-]?secret)",
                str(key),
                re.I,
            ):
                raise DaimonManifestError(
                    f"secret-shaped field is forbidden: {key}"
                )
            _reject_embedded_secrets(item)
    elif isinstance(value, list):
        for item in value:
            _reject_embedded_secrets(item)
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS):
            raise DaimonManifestError("embedded secret-shaped value is forbidden")


def validate_manifest(value: Any) -> dict[str, Any]:
    manifest = dict(_closed(value, _TOP_KEYS, "daimon manifest"))
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise DaimonManifestError(f"manifest must use {MANIFEST_SCHEMA}")
    _identifier(manifest["manifest_id"], "manifest_id")
    _identifier(manifest["subject"], "subject")
    _reject_embedded_secrets(manifest)

    definition = _closed(manifest["definition"], _DEFINITION_KEYS, "definition")
    _uri(definition["source_uri"], "definition.source_uri")
    _hash(definition["source_sha256"], "definition.source_sha256")
    _hash(definition["species_sha256"], "definition.species_sha256")

    if not isinstance(manifest["lineage"], list):
        raise DaimonManifestError("lineage must be a list")
    lineage_ids = set()
    for item in manifest["lineage"]:
        entry = _closed(item, _LINEAGE_KEYS, "lineage entry")
        identity = _identifier(entry["species_id"], "lineage.species_id")
        if identity in lineage_ids:
            raise DaimonManifestError("lineage species IDs must be unique")
        lineage_ids.add(identity)
        _hash(entry["definition_sha256"], "lineage.definition_sha256")

    provenance = _closed(
        manifest["provenance"], _PROVENANCE_KEYS, "provenance"
    )
    _string(provenance["generated_at"], "provenance.generated_at")
    _identifier(provenance["generator"], "provenance.generator")
    _uri(provenance["source_repository"], "provenance.source_repository")
    if not _GIT_SHA.fullmatch(
        _string(provenance["source_commit"], "provenance.source_commit")
    ):
        raise DaimonManifestError("provenance.source_commit must be a full Git SHA")

    portability = _closed(
        manifest["portability"], _PORTABILITY_KEYS, "portability"
    )
    if portability["generation_scheme"] != "compaii-state-manifest/v2":
        raise DaimonManifestError("unsupported portability generation scheme")
    if not _UUID.fullmatch(
        _string(portability["generation_id"], "portability.generation_id")
    ):
        raise DaimonManifestError("portability.generation_id must be a UUID")
    if not _GIT_SHA.fullmatch(
        _string(portability["source_commit"], "portability.source_commit")
    ):
        raise DaimonManifestError("portability.source_commit must be a full Git SHA")
    _hash(
        portability["artifact_index_sha256"],
        "portability.artifact_index_sha256",
    )
    _refs([portability["restore_contract"]], "portability.restore_contract")

    if not isinstance(manifest["trust_domains"], list):
        raise DaimonManifestError("trust_domains must be a list")
    trust_domains = {}
    for item in manifest["trust_domains"]:
        entry = _closed(item, _TRUST_KEYS, "trust domain")
        identity = _identifier(entry["id"], "trust_domain.id")
        if identity in trust_domains:
            raise DaimonManifestError("trust domain IDs must be unique")
        classifications = set(
            _unique_strings(
                entry["classifications"], "trust_domain.classifications"
            )
        )
        if not classifications or not classifications <= CLASSIFICATIONS:
            raise DaimonManifestError("trust domain classifications are invalid")
        schemes = set(
            _unique_strings(
                entry["endpoint_schemes"], "trust_domain.endpoint_schemes"
            )
        )
        if not schemes or not schemes <= ENDPOINT_SCHEMES:
            raise DaimonManifestError("trust domain endpoint schemes are invalid")
        _refs(entry["policy_refs"], "trust_domain.policy_refs")
        trust_domains[identity] = entry

    embodiment = _closed(
        manifest["embodiment"], _EMBODIMENT_KEYS, "embodiment"
    )
    _identifier(embodiment["realm"], "embodiment.realm")
    _identifier(embodiment["body_id"], "embodiment.body_id")
    for field in ("surfaces", "sensors", "actuators", "tools"):
        _unique_strings(embodiment[field], f"embodiment.{field}")

    endpoint_ids = set()
    for item in manifest["memory_endpoints"]:
        entry = _closed(item, _MEMORY_KEYS, "memory endpoint")
        identity = _identifier(entry["id"], "memory_endpoint.id")
        if identity in endpoint_ids:
            raise DaimonManifestError("endpoint IDs must be unique")
        endpoint_ids.add(identity)
        if entry["role"] not in MEMORY_ROLES or entry["authority"] not in AUTHORITY:
            raise DaimonManifestError("memory endpoint role/authority is invalid")
        scheme = urlparse(
            _uri(entry["uri"], "memory_endpoint.uri", ENDPOINT_SCHEMES)
        ).scheme
        domain = entry["trust_domain"]
        if domain not in trust_domains:
            raise DaimonManifestError("memory endpoint trust domain is unknown")
        if scheme not in trust_domains[domain]["endpoint_schemes"]:
            raise DaimonManifestError(
                "memory endpoint scheme is not allowed by its trust domain"
            )
        classifications = set(
            _unique_strings(entry["classifications"], "memory classifications")
        )
        if not classifications <= set(trust_domains[domain]["classifications"]):
            raise DaimonManifestError(
                "memory classifications exceed trust domain policy"
            )
        modes = set(_unique_strings(entry["modes"], "memory modes"))
        if not modes or not modes <= {"read", "write", "publish"}:
            raise DaimonManifestError("memory endpoint modes are invalid")
        _refs(entry["policy_refs"], "memory_endpoint.policy_refs")

    for item in manifest["communication_endpoints"]:
        entry = _closed(item, _COMMUNICATION_KEYS, "communication endpoint")
        identity = _identifier(entry["id"], "communication_endpoint.id")
        if identity in endpoint_ids:
            raise DaimonManifestError("endpoint IDs must be unique")
        endpoint_ids.add(identity)
        if entry["scope"] not in COMMUNICATION_SCOPES:
            raise DaimonManifestError("communication scope is invalid")
        scheme = urlparse(
            _uri(entry["uri"], "communication_endpoint.uri", ENDPOINT_SCHEMES)
        ).scheme
        domain = entry["trust_domain"]
        if domain not in trust_domains:
            raise DaimonManifestError(
                "communication endpoint trust domain is unknown"
            )
        if scheme not in trust_domains[domain]["endpoint_schemes"]:
            raise DaimonManifestError(
                "communication scheme is not allowed by its trust domain"
            )
        classifications = set(
            _unique_strings(
                entry["classifications"], "communication classifications"
            )
        )
        if not classifications <= set(trust_domains[domain]["classifications"]):
            raise DaimonManifestError(
                "communication classifications exceed trust domain policy"
            )
        modes = set(_unique_strings(entry["modes"], "communication modes"))
        if not modes or not modes <= {"send", "receive", "coordinate"}:
            raise DaimonManifestError("communication modes are invalid")
        _refs(entry["policy_refs"], "communication_endpoint.policy_refs")

    if not isinstance(manifest["capabilities"], list):
        raise DaimonManifestError("capabilities must be a list")
    capabilities = {}
    for item in manifest["capabilities"]:
        entry = _closed(item, _CAPABILITY_KEYS, "capability")
        identity = _identifier(entry["id"], "capability.id")
        if identity in capabilities:
            raise DaimonManifestError("capability IDs must be unique")
        if entry["maturity"] not in MATURITY:
            raise DaimonManifestError("capability maturity is invalid")
        _identifier(entry["kind"], "capability.kind")
        _string(entry["version"], "capability.version")
        _unique_strings(entry["interfaces"], "capability.interfaces")
        _unique_strings(entry["task_labels"], "capability.task_labels")
        domains = set(
            _unique_strings(entry["trust_domains"], "capability.trust_domains")
        )
        if not domains <= set(trust_domains):
            raise DaimonManifestError("capability trust domain is unknown")
        evidence = _refs(entry["evidence"], "capability.evidence")
        if entry["maturity"] == "implemented" and not evidence:
            raise DaimonManifestError(
                "implemented capability requires immutable evidence"
            )
        _unique_strings(entry["constraints"], "capability.constraints")
        capabilities[identity] = entry

    for field in ("sensors", "actuators", "tools"):
        unknown = set(embodiment[field]) - set(capabilities)
        if unknown:
            raise DaimonManifestError(
                f"embodiment.{field} references unknown capabilities: "
                + ", ".join(sorted(unknown))
            )

    if not isinstance(manifest["secret_refs"], list):
        raise DaimonManifestError("secret_refs must be a list")
    secret_names = set()
    for item in manifest["secret_refs"]:
        entry = _closed(item, _SECRET_REF_KEYS, "secret reference")
        name = _identifier(entry["name"], "secret_ref.name")
        if name in secret_names:
            raise DaimonManifestError("secret reference names must be unique")
        secret_names.add(name)
        _uri(entry["reference"], "secret_ref.reference", REFERENCE_SCHEMES)

    governance = _closed(
        manifest["governance"], _GOVERNANCE_KEYS, "governance"
    )
    _string(governance["owner"], "governance.owner")
    _refs(governance["decision_refs"], "governance.decision_refs")
    _refs(
        governance["authorization_policy_refs"],
        "governance.authorization_policy_refs",
    )
    return manifest


def validate_task(value: Any) -> dict[str, Any]:
    task = dict(_closed(value, _TASK_KEYS, "task requirements"))
    if task["schema"] != TASK_SCHEMA:
        raise DaimonManifestError(f"task must use {TASK_SCHEMA}")
    _identifier(task["task_id"], "task_id")
    for field in (
        "required_capabilities",
        "required_tools",
        "required_trust_domains",
    ):
        _unique_strings(task[field], field)
    if task["required_classification"] not in CLASSIFICATIONS:
        raise DaimonManifestError("required_classification is invalid")
    if task["required_realm"] is not None:
        _identifier(task["required_realm"], "required_realm")
    if not isinstance(task["allow_partial"], bool):
        raise DaimonManifestError("allow_partial must be boolean")
    return task


def validate_concept_inventory(value: Any) -> dict[str, Any]:
    inventory = dict(_closed(value, _INVENTORY_KEYS, "concept inventory"))
    if inventory["schema"] != INVENTORY_SCHEMA:
        raise DaimonManifestError(f"inventory must use {INVENTORY_SCHEMA}")
    source = _closed(
        inventory["source"], _INVENTORY_SOURCE_KEYS, "inventory source"
    )
    _uri(source["uri"], "inventory.source.uri")
    _string(source["observed_at"], "inventory.source.observed_at")
    _string(source["source_last_edited"], "inventory.source.source_last_edited")
    _hash(source["sha256"], "inventory.source.sha256")
    _string(inventory["governance_owner"], "inventory.governance_owner")
    if not isinstance(inventory["concepts"], list) or not inventory["concepts"]:
        raise DaimonManifestError("concept inventory must not be empty")
    seen = set()
    for item in inventory["concepts"]:
        concept = _closed(item, _CONCEPT_KEYS, "concept")
        identity = _identifier(concept["id"], "concept.id")
        if identity in seen:
            raise DaimonManifestError("concept IDs must be unique")
        seen.add(identity)
        _string(concept["source_expression"], "concept.source_expression")
        classification = concept["classification"]
        if classification not in {
            "implemented",
            "partial",
            "metaphor",
            "aspirational",
        }:
            raise DaimonManifestError("concept classification is invalid")
        mapping = concept["executable_mapping"]
        if classification in {"implemented", "partial"}:
            _string(mapping, "concept.executable_mapping")
        elif mapping is not None and not isinstance(mapping, str):
            raise DaimonManifestError(
                "concept executable_mapping must be string or null"
            )
        if classification == "metaphor" and mapping is not None:
            raise DaimonManifestError("metaphor cannot be executable policy")
        _string(concept["status_date"], "concept.status_date")
        _string(concept["notes"], "concept.notes")
    return inventory


def select_manifest(manifest_value: Any, task_value: Any) -> dict[str, Any]:
    manifest = validate_manifest(manifest_value)
    task = validate_task(task_value)
    capabilities = {item["id"]: item for item in manifest["capabilities"]}
    tools = set(manifest["embodiment"]["tools"])
    trust = {item["id"]: item for item in manifest["trust_domains"]}
    reasons = []
    warnings = []
    matched = []

    for capability_id in task["required_capabilities"]:
        capability = capabilities.get(capability_id)
        if capability is None:
            reasons.append(f"missing capability: {capability_id}")
            continue
        if capability["maturity"] == "aspirational":
            reasons.append(f"capability is aspirational: {capability_id}")
            continue
        if capability["maturity"] == "partial" and not task["allow_partial"]:
            reasons.append(f"capability is only partial: {capability_id}")
            continue
        missing_domains = sorted(
            set(task["required_trust_domains"])
            - set(capability["trust_domains"])
        )
        if missing_domains:
            reasons.append(
                f"capability {capability_id} does not cover required trust "
                f"domains: {', '.join(missing_domains)}"
            )
            continue
        matched.append(capability_id)
        warnings.extend(
            f"{capability_id}: {constraint}"
            for constraint in capability["constraints"]
        )

    for tool in task["required_tools"]:
        if tool not in tools:
            reasons.append(f"missing embodied tool: {tool}")
    for domain_id in task["required_trust_domains"]:
        if domain_id not in trust:
            reasons.append(f"missing trust domain: {domain_id}")
            continue
        if task["required_classification"] not in trust[domain_id][
            "classifications"
        ]:
            reasons.append(
                f"classification {task['required_classification']} is not "
                f"allowed in trust domain {domain_id}"
            )
    realm = task["required_realm"]
    if realm is not None and realm != manifest["embodiment"]["realm"]:
        reasons.append(
            f"realm mismatch: requires {realm}, has "
            f"{manifest['embodiment']['realm']}"
        )

    return {
        "schema": DECISION_SCHEMA,
        "task_id": task["task_id"],
        "manifest_id": manifest["manifest_id"],
        "manifest_sha256": manifest_sha256(manifest),
        "eligible_for_consideration": not reasons,
        "authorization": "not-evaluated",
        "matched_capabilities": matched,
        "reasons": reasons,
        "warnings": sorted(set(warnings)),
        "policy_refs": manifest["governance"]["authorization_policy_refs"],
    }
