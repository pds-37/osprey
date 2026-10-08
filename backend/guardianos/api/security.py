"""FastAPI route policy that authenticates every state-changing endpoint."""

from fastapi import APIRouter, Depends

from guardianos.core.security import UserRole, require_role


class SecuredAPIRouter(APIRouter):
    """Require an authenticated viewer for reads and engineer/admin roles for writes."""

    def add_api_route(self, path: str, endpoint, **kwargs):
        methods = {str(method).upper() for method in (kwargs.get("methods") or ["GET"])}
        if methods.intersection({"POST", "PUT", "PATCH", "DELETE"}):
            endpoint_name = getattr(endpoint, "__name__", "").lower()
            path_lower = path.lower()
            minimum_role = UserRole.SECURITY_ENGINEER
            if "approve" in endpoint_name or path_lower.endswith("/approve") or "/users" in path_lower or "/config" in path_lower:
                minimum_role = UserRole.ADMIN
            dependencies = list(kwargs.get("dependencies") or [])
            dependencies.append(Depends(require_role(minimum_role)))
            kwargs["dependencies"] = dependencies
        elif "GET" in methods:
            dependencies = list(kwargs.get("dependencies") or [])
            dependencies.append(Depends(require_role(UserRole.VIEWER)))
            kwargs["dependencies"] = dependencies
        return super().add_api_route(path, endpoint, **kwargs)
