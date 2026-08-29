"""Models package for NetWatch AI.

Importing every model here registers it with the SQLAlchemy ``Base.metadata``,
which is required for ``Base.metadata.create_all()`` to create all tables.
"""

from app.models.ai_insight import AiInsight
from app.models.alert import Alert
from app.models.alert_evidence import AlertEvidence
from app.models.baseline import BehavioralBaseline
from app.models.connection import NetworkConnection
from app.models.detection_rule import DetectionRule
from app.models.device import Device
from app.models.notification import Notification
from app.models.packet import Packet
from app.models.report import Report
from app.models.setting import Setting
from app.models.statistics import ProtocolStatistic, TrafficStatistic
from app.models.system_status import SystemStatus
from app.models.user import User

__all__ = [
    "AiInsight",
    "Alert",
    "AlertEvidence",
    "BehavioralBaseline",
    "DetectionRule",
    "Device",
    "NetworkConnection",
    "Notification",
    "Packet",
    "ProtocolStatistic",
    "Report",
    "Setting",
    "SystemStatus",
    "TrafficStatistic",
    "User",
]
