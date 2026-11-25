"""
Exportación centralizada de routers FastAPI.
"""

from app.routers import admin, auth, dependencies, users, views

__all__ = [
    "admin",
    "auth",
    "dependencies",
    "users",
    "views",
]
