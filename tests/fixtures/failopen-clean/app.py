"""Near misses for every detector. This file must produce zero findings.

Each construct here is one small step away from a defect: a real default instead of an
empty one, an empty default on a non-URL variable, a gate that closes, a gate whose
permissive return is inside a branch, and a handler that actually handles.
"""

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


logger = logging.getLogger(__name__)

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.example.com")
RETRY_COUNT = os.getenv("RETRY_COUNT", "")


def check_access(user, resource):
    if user.is_admin:
        return True
    if resource.owner_id == user.id:
        return True
    return False


def has_permission(user):
    if user.is_admin:
        return True
    else:
        return False


def load_settings(path):
    try:
        return open(path).read()
    except Exception:
        logger.exception("could not read %s", path)
        return None


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
)
