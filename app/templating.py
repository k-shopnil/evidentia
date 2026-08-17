from fastapi.templating import Jinja2Templates
import json

from app.config import settings

templates = Jinja2Templates(directory="app/templates")
templates.env.globals["settings"] = settings


def pretty_details(details):
    if not details:
        return "-"
    if isinstance(details, dict):
        data = details
    else:
        try:
            data = json.loads(details)
        except (ValueError, TypeError):
            return str(details)[:200]
    if isinstance(data, dict):
        return ", ".join(f"{k}: {v}" for k, v in data.items())
    return str(data)[:200]


templates.env.filters["pretty_details"] = pretty_details