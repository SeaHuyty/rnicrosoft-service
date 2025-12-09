"""Someth Antivirus UI Module"""
from .styles import DARK_STYLESHEET, COLORS
from .dashboard import DashboardWidget
from .settings import SettingsWidget
from .alerts import AlertsWidget
from .quarantine import QuarantineWidget

__all__ = [
    'DARK_STYLESHEET',
    'COLORS',
    'DashboardWidget',
    'SettingsWidget',
    'AlertsWidget',
    'QuarantineWidget'
]
