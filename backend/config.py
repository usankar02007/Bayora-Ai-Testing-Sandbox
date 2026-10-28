import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Load environment variables without overwriting existing environment
load_dotenv(BASE_DIR / ".env")

APP_NAME = "Bayora AI Safety Platform"
API_VERSION = "v1"

# Team Authentication Tokens
RED_TEAM_TOKEN = os.getenv("RED_TEAM_TOKEN", "bayora-red-team-default-token-2026")
BLUE_TEAM_TOKEN = os.getenv("BLUE_TEAM_TOKEN", "bayora-blue-team-default-token-2026")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "bayora-admin-default-token-2026")

# Database Configuration
# Default attempts Postgres, fallback to SQLite if unreachable
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/bayora")
SQLITE_FALLBACK_URL = f"sqlite:///{BASE_DIR / 'bayora.db'}"

# TinyFish Agent Integration
TINYFISH_API_KEY = os.getenv("TINYFISH_API_KEY", "")
TINYFISH_URL = os.getenv("TINYFISH_URL", "https://agent.tinyfish.ai/v1/automation/run")

# Docker Sandbox
SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "bayora-sandbox:dev")

# AI Model Provider Configuration
ALLOW_REMOTE_MODELS = os.getenv("ALLOW_REMOTE_MODELS", "false").lower() in ("true", "1", "yes")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
LOCAL_MODEL_URL = os.getenv("LOCAL_MODEL_URL", "http://localhost:11434/v1/chat/completions")
LOCAL_MODEL_NAME = os.getenv("LOCAL_MODEL_NAME", "llama3")

# Execution limits
MAX_PROMPT_LENGTH = int(os.getenv("MAX_PROMPT_LENGTH", "4000"))
MAX_OUTPUT_LENGTH = int(os.getenv("MAX_OUTPUT_LENGTH", "8000"))
EXECUTION_TIMEOUT_SECONDS = int(os.getenv("EXECUTION_TIMEOUT_SECONDS", "15"))