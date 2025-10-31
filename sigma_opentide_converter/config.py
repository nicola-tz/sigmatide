# Sigma to OpenTide Converter Configuration

# Default settings for the converter
DEFAULT_TARGET_SYSTEMS = ["defender_for_endpoint", "splunk"]
DEFAULT_OUTPUT_SCHEMA = "mdr::2.1"
DEFAULT_TLP = "amber+strict"

# Field mappings for different target systems
FIELD_MAPPINGS = {
    "defender_for_endpoint": {
        "severity_map": {
            "informational": "Informational",
            "low": "Low", 
            "medium": "Medium",
            "high": "High",
            "critical": "Critical"
        },
        "tactic_map": {
            "initial_access": "InitialAccess",
            "execution": "Execution",
            "persistence": "Persistence", 
            "privilege_escalation": "PrivilegeEscalation",
            "defense_evasion": "DefenseEvasion",
            "credential_access": "CredentialAccess",
            "discovery": "Discovery",
            "lateral_movement": "LateralMovement",
            "collection": "Collection",
            "command_and_control": "CommandAndControl",
            "exfiltration": "Exfiltration",
            "impact": "Impact"
        }
    }
}

# Manual completion warning messages
MANUAL_COMPLETION_WARNINGS = [
    "Scheduling configuration (frequency, lookback, cron)",
    "Impacted entities (device, user, mailbox)",
    "Review and adjust queries as needed",
    "Look for '# MANUAL COMPLETION REQUIRED' comments in the output"
]