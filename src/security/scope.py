"""Authorization scope — defines the boundaries of an agent's authority.

Every task must have a defined AuthorizationScope. The SecurityPolicyEngine
validates every tool call against this scope.
"""

from __future__ import annotations

import ipaddress
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class OperationType(str, Enum):
    """Types of operations an agent can perform."""

    # Read-only, low risk
    ASSET_DISCOVER = "asset_discover"       # Subdomain enum, DNS queries
    PORT_SCAN = "port_scan"                  # TCP/UDP port scanning
    FINGERPRINT = "fingerprint"              # Service/OS fingerprinting

    # Active scanning, medium risk
    VULNERABILITY_SCAN = "vulnerability_scan"  # Automated vulnerability scanning
    WEB_SCAN = "web_scan"                       # Web application scanning
    CODE_AUDIT = "code_audit"                   # Static code analysis

    # Intrusive, high risk
    EXPLOIT = "exploit"                      # Active exploitation
    COMMAND_EXEC = "command_exec"            # Arbitrary command execution
    DATA_EXFIL = "data_exfil"                # Data exfiltration

    # Meta
    READ_FILE = "read_file"                  # Read local files
    WRITE_FILE = "write_file"                # Write to local files
    NETWORK_OUT = "network_out"              # Outbound network connections


class ScanIntensity(str, Enum):
    """How aggressively the agent can scan."""

    PASSIVE = "passive"        # No packets sent to target (DNS, WHOIS, search engines)
    ACTIVE = "active"          # Standard scanning (port scan, version probe)
    INTRUSIVE = "intrusive"    # Exploitation, brute force, fuzzing


# Map intensity to allowed operation types
INTENSITY_OPERATIONS: dict[ScanIntensity, set[OperationType]] = {
    ScanIntensity.PASSIVE: {
        OperationType.ASSET_DISCOVER,
        OperationType.READ_FILE,
        OperationType.CODE_AUDIT,
    },
    ScanIntensity.ACTIVE: {
        OperationType.ASSET_DISCOVER,
        OperationType.PORT_SCAN,
        OperationType.FINGERPRINT,
        OperationType.VULNERABILITY_SCAN,
        OperationType.WEB_SCAN,
        OperationType.CODE_AUDIT,
        OperationType.READ_FILE,
        OperationType.WRITE_FILE,
    },
    ScanIntensity.INTRUSIVE: {
        OperationType.ASSET_DISCOVER,
        OperationType.PORT_SCAN,
        OperationType.FINGERPRINT,
        OperationType.VULNERABILITY_SCAN,
        OperationType.WEB_SCAN,
        OperationType.CODE_AUDIT,
        OperationType.EXPLOIT,
        OperationType.COMMAND_EXEC,
        OperationType.DATA_EXFIL,
        OperationType.READ_FILE,
        OperationType.WRITE_FILE,
        OperationType.NETWORK_OUT,
    },
}

# Operations that always require human approval
HIGH_RISK_OPERATIONS: set[OperationType] = {
    OperationType.EXPLOIT,
    OperationType.COMMAND_EXEC,
    OperationType.DATA_EXFIL,
}


@dataclass
class AuthorizationScope:
    """Defines the authorization boundaries for a security assessment task.

    Every tool call is validated against this scope before execution.

    Example::

        scope = AuthorizationScope(
            allowed_targets=["192.168.1.0/24", "example.com"],
            allowed_operations=[OperationType.PORT_SCAN, OperationType.VULNERABILITY_SCAN],
            prohibited_targets=["192.168.1.1"],  # Don't touch the gateway
            intensity=ScanIntensity.ACTIVE,
            requires_human_approval=True,
            expires_in_hours=4,
        )
    """

    scope_id: str = field(default_factory=lambda: f"scope_{uuid.uuid4().hex[:12]}")
    allowed_targets: list[str] = field(default_factory=list)
    allowed_operations: list[OperationType] = field(default_factory=list)
    prohibited_targets: list[str] = field(default_factory=list)
    intensity: ScanIntensity = ScanIntensity.PASSIVE
    requires_human_approval: bool = True
    expires_at: float = field(default_factory=lambda: time.time() + 3600 * 8)
    created_by: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        # Always include intensity-appropriate operations
        intensity_ops = INTENSITY_OPERATIONS.get(self.intensity, set())
        self.allowed_operations = list(set(self.allowed_operations) | intensity_ops)

    # ------------------------------------------------------------------
    # Target validation
    # ------------------------------------------------------------------
    def is_target_allowed(self, target: str) -> bool:
        """Check if a target is within the authorized scope.

        Returns True if the target matches any allowed_targets
        and does NOT match any prohibited_targets.
        """
        # Check prohibited list first (deny takes precedence)
        for prohibited in self.prohibited_targets:
            if self._target_matches(target, prohibited):
                return False

        # Check allowed list
        if not self.allowed_targets:
            return True  # No restrictions — allow all

        for allowed in self.allowed_targets:
            if self._target_matches(target, allowed):
                return True

        return False

    def is_operation_allowed(self, operation: OperationType) -> bool:
        """Check if an operation type is authorized."""
        return operation in self.allowed_operations

    def is_high_risk(self, operation: OperationType) -> bool:
        """Check if an operation requires human approval."""
        return operation in HIGH_RISK_OPERATIONS

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def remaining_minutes(self) -> float:
        return max(0.0, (self.expires_at - time.time()) / 60.0)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _target_matches(target: str, pattern: str) -> bool:
        """Check if target matches a pattern (IP, CIDR, or domain)."""
        # Exact match
        if target == pattern:
            return True

        # CIDR match
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(target)
            return addr in network
        except ValueError:
            pass

        # Domain suffix match (e.g., "*.example.com" matches "sub.example.com")
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            if target.endswith(suffix):
                return True

        return False

    def to_dict(self) -> dict:
        return {
            "scope_id": self.scope_id,
            "allowed_targets": self.allowed_targets,
            "allowed_operations": [op.value for op in self.allowed_operations],
            "prohibited_targets": self.prohibited_targets,
            "intensity": self.intensity.value,
            "requires_human_approval": self.requires_human_approval,
            "expires_at": self.expires_at,
            "created_by": self.created_by,
            "notes": self.notes,
        }
