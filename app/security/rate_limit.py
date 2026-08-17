from slowapi import Limiter
from slowapi.util import get_remote_address
from app.config import settings


def get_rate_limit_key(request):
    return get_remote_address(request)


limiter = Limiter(
    key_func=get_rate_limit_key,
    enabled=settings.RATE_LIMIT_ENABLED,
    default_limits=[settings.RATE_LIMIT_GENERAL] if settings.RATE_LIMIT_ENABLED else [],
)


def get_limiter():
    return limiter