"""
Duo Admin API client wrapper.
Handles authentication, pagination, and error handling for all Admin API endpoints.
"""

import os
import duo_client
from dotenv import load_dotenv
from pathlib import Path

# Load config from project-level .env
_config_path = Path(__file__).parent.parent / "config" / ".env"
load_dotenv(_config_path)


def get_admin_client() -> duo_client.Admin:
    """Create and return an authenticated Duo Admin API client."""
    ikey = os.environ.get("DUO_IKEY")
    skey = os.environ.get("DUO_SKEY")
    host = os.environ.get("DUO_HOST")

    if not all([ikey, skey, host]):
        raise EnvironmentError(
            "Missing Duo credentials. Ensure DUO_IKEY, DUO_SKEY, and DUO_HOST "
            "are set in config/.env"
        )

    admin_api = duo_client.Admin(
        ikey=ikey,
        skey=skey,
        host=host,
    )
    return admin_api


def paginated_fetch(admin: duo_client.Admin, method_name: str, page_size: int = 300, **kwargs):
    """
    Generic paginated fetch for any Admin API list endpoint.
    The duo_client library methods that support pagination accept limit/offset params.
    """
    all_results = []
    offset = 0

    while True:
        method = getattr(admin, method_name)
        try:
            results = method(limit=str(page_size), offset=str(offset), **kwargs)
        except TypeError:
            # Some endpoints don't support limit/offset — call without
            results = method(**kwargs)
            if isinstance(results, list):
                return results
            return [results] if results else []

        if not results:
            break

        all_results.extend(results)

        # If we got fewer than page_size, we've hit the end
        if len(results) < page_size:
            break

        offset += page_size

    return all_results
