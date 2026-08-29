"""Repositories package for NetWatch AI.

Repositories wrap the database session and hide low-level SQLAlchemy queries
behind reusable methods. Following the architecture in the design document:

    API -> Service Layer -> Repository Layer -> Database
"""

from app.repositories.alert import AlertRepository
from app.repositories.base import BaseRepository
from app.repositories.baseline import BaselineRepository
from app.repositories.connection import ConnectionRepository
from app.repositories.detection_rule import DetectionRuleRepository
from app.repositories.device import DeviceRepository
from app.repositories.packet import PacketRepository
from app.repositories.statistics import StatisticsRepository

__all__ = [
    "AlertRepository",
    "BaseRepository",
    "BaselineRepository",
    "ConnectionRepository",
    "DetectionRuleRepository",
    "DeviceRepository",
    "PacketRepository",
    "StatisticsRepository",
]
