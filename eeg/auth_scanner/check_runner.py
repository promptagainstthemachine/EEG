"""
EEG - Config-driven Check Runner
Executes checks defined in YAML configs for auth scanners.
"""

from typing import Dict, Any, Optional, Callable, Tuple
from eeg.collector import Collector, Finding, Severity
from eeg.config import ConfigLoader


class CheckRunner:
    """
    Executes live checks based on YAML configuration.
    Provides a bridge between config definitions and scanner implementations.
    """
    
    def __init__(self, cloud: str, collector: Collector):
        self.cloud = cloud
        self.collector = collector
        self.config = ConfigLoader.load(f"{cloud}_dynamic")
        self.thresholds = ConfigLoader.load("thresholds")
        
    def get_check(self, check_id: str) -> Optional[Dict[str, Any]]:
        """Get check definition by ID."""
        for check in self.config.get("checks", []):
            if check.get("id") == check_id:
                return check
        return None
    
    def is_enabled(self, check_id: str) -> bool:
        """Check if a specific check is enabled."""
        check = self.get_check(check_id)
        if check is None:
            return True  # Default to enabled
        return check.get("enabled", True)
    
    def get_severity(self, check_id: str) -> Severity:
        """Get severity for a check from config."""
        check = self.get_check(check_id)
        if check is None:
            return Severity.MEDIUM
        sev_str = check.get("severity", "MEDIUM").upper()
        return Severity[sev_str] if sev_str in Severity.__members__ else Severity.MEDIUM
    
    def get_threshold(self, key: str, default: Any = None) -> Any:
        """Get threshold value using dot-notation key."""
        return ConfigLoader.get_threshold(key, default)
    
    def create_finding(
        self,
        check_id: str,
        file_path: str,
        code_snippet: str = "",
        message_override: str = None,
        line_number: int = 0,
    ) -> Finding:
        """
        Create a Finding from a check definition.
        
        Args:
            check_id: Check ID to look up
            file_path: Resource identifier (e.g., "live:guardrail:my-guardrail")
            code_snippet: Relevant config snippet
            message_override: Override the default message
            line_number: Always 0 for live checks
        """
        check = self.get_check(check_id)
        
        if check is None:
            # Fallback for undefined checks
            return Finding(
                rule_id=check_id,
                severity=Severity.MEDIUM,
                category="unknown",
                cloud_env=self.cloud,
                file_path=file_path,
                line_number=line_number,
                code_snippet=code_snippet,
                message=message_override or f"Check {check_id} triggered",
                recommendation="See documentation for details.",
            )
        
        return Finding(
            rule_id=check_id,
            severity=self.get_severity(check_id),
            category=check.get("category", "general"),
            cloud_env=self.cloud,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            message=message_override or check.get("description", ""),
            recommendation=check.get("recommendation", ""),
            owasp_llm=check.get("owasp_llm"),
            cwe=check.get("cwe"),
        )
    
    def add_finding_if_enabled(
        self,
        check_id: str,
        file_path: str,
        code_snippet: str = "",
        message_override: str = None,
    ) -> bool:
        """
        Create and add finding if the check is enabled.
        Returns True if finding was added.
        """
        if not self.is_enabled(check_id):
            return False
        
        finding = self.create_finding(
            check_id=check_id,
            file_path=file_path,
            code_snippet=code_snippet,
            message_override=message_override,
        )
        self.collector.add_finding(finding)
        return True
    
    def get_api_command(self, category: str, command_name: str) -> Optional[str]:
        """Get CLI command template from config."""
        api_config = self.config.get("api_config", {})
        for service_config in api_config.values():
            commands = service_config.get("commands", {})
            if command_name in commands:
                return commands[command_name]
        return None
    
    def get_checks_by_category(self, category: str) -> list:
        """Get all enabled checks for a category."""
        checks = self.config.get("checks", [])
        return [
            c for c in checks 
            if c.get("category") == category and c.get("enabled", True)
        ]


def get_threshold(cloud: str, key: str, default: Any = None) -> Any:
    """
    Convenience function to get threshold without instantiating CheckRunner.
    
    Args:
        cloud: Cloud provider (unused, kept for API compatibility)
        key: Dot-notation key (e.g., 'guardrail.min_input_strength')
        default: Default value if not found
    """
    return ConfigLoader.get_threshold(key, default)


def get_check_config(cloud: str, check_id: str) -> Optional[Dict[str, Any]]:
    """
    Convenience function to get check config.
    """
    return ConfigLoader.get_check(cloud, check_id)


def is_check_enabled(cloud: str, check_id: str) -> bool:
    """
    Convenience function to check if a check is enabled.
    """
    return ConfigLoader.is_check_enabled(cloud, check_id)
