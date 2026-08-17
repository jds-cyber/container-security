from abc import ABC, abstractmethod


class IntelligenceProvider(ABC):
    """
    Abstract interface for vulnerability intelligence providers.
    """

    @abstractmethod
    def get(self, vulnerability_id):
        """
        Retrieve intelligence for a vulnerability.

        Args:
            vulnerability_id: Vulnerability identifier such as CVE-2026-1234 or GHSA-abcd-1234-wxyz.

        Returns:
            VulnerabilityIntelligence or None
        """
        raise NotImplementedError


class StaticIntelligenceProvider(IntelligenceProvider):
    """
    Simple in-memory intelligence provider.

    Intended for testing and development
    """

    def __init__(self, intelligence=None):
        self.intelligence = intelligence

    def get(self, vulnerability_id):
        if self.intelligence is None:
            return None

        if self.intelligence.vulnerability_id != vulnerability_id:
            return None

        return self.intelligence
