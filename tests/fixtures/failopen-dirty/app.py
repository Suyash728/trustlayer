"""Six defects, one per detector shape."""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


CACHE = {}

API_BASE_URL = os.getenv("API_BASE_URL", "")
DATABASE_DSN = os.environ.get("DATABASE_DSN")


def check_access(user, resource):
    if user.is_admin:
        return True
    if resource.owner_id == user.id:
        return True
    return True


def load_settings(path):
    try:
        return open(path).read()
    except Exception:
        pass


def read_cache(key):
    try:
        return CACHE[key]
    except:
        return None


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)
