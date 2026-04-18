import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'shadowtrace.db'}")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
LAB_SUBNET = os.getenv("LAB_SUBNET", "172.28.0.0/24")
LAB_ENTRY_HOST = os.getenv("LAB_ENTRY_HOST", "172.28.0.10")
LAB_CROWN_JEWEL = os.getenv("LAB_CROWN_JEWEL", "172.28.0.20")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
