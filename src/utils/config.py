import os
from dotenv import load_dotenv

# Load environment variables from .env.local
load_dotenv('.env.local')

# API Keys
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')

# Logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# Validation
if not ANTHROPIC_API_KEY:
    raise ValueError("ANTHROPIC_API_KEY not set in .env.local")