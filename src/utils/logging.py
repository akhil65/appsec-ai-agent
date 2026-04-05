import logging
import sys
from src.utils.config import LOG_LEVEL

def setup_logger(name: str) -> logging.Logger:
    """Configure and return a logger instance"""
    
    logger = logging.getLogger(name)
    
    # Only add handler if not already configured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(LOG_LEVEL)
    
    return logger

# Root logger
root_logger = setup_logger('appsec-ai-agent')