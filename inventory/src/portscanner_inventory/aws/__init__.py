"""AWS adapters and ownership validation."""

from .ownership import OwnershipValidator
from .resolve import Ec2Resolver

__all__ = ["Ec2Resolver", "OwnershipValidator"]
