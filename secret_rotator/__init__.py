"""secret-rotator: rotate API keys safely across providers."""
from .engine import RotationEngine, RotationResult, RotationError
from .providers import Provider, MockProvider
from .stores import SecretStore, MockStore
from .verifiers import Verifier, AlwaysOKVerifier, AlwaysFailVerifier

__version__ = "0.1.0"
__all__ = ["RotationEngine", "RotationResult", "RotationError",
           "Provider", "MockProvider",
           "SecretStore", "MockStore",
           "Verifier", "AlwaysOKVerifier", "AlwaysFailVerifier"]
