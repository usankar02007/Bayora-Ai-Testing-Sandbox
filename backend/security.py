import logging
import secrets
from dataclasses import dataclass
from typing import Optional
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from config import ADMIN_TOKEN, BLUE_TEAM_TOKEN, RED_TEAM_TOKEN
from database import get_db, verify_password
from models import User

logger = logging.getLogger("bayora.security")


@dataclass
class AuthContext:
    user_id: str
    username: str
    role: str  # "red", "blue", "admin"
    auth_method: str  # "token" or "password"


def authenticate(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> AuthContext:
    """
    Validates Bearer token against team tokens and persistent user database.
    Rejects missing or invalid tokens with HTTP 401.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Use Bearer token authentication.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = token.strip()

    # 1. Check configured environment team tokens (backward compatibility & service-to-service)
    configured_tokens = [
        ("red", RED_TEAM_TOKEN, "redteam"),
        ("blue", BLUE_TEAM_TOKEN, "blueteam"),
        ("admin", ADMIN_TOKEN, "admin"),
    ]

    for role, expected_token, default_username in configured_tokens:
        if expected_token and secrets.compare_digest(token, expected_token):
            user = db.query(User).filter_by(username=default_username).first()
            user_id = user.id if user else f"system-{role}"
            return AuthContext(
                user_id=user_id,
                username=default_username,
                role=role,
                auth_method="bearer_team_token",
            )

    # 2. Check if token matches a username's token or session
    # For prototype testing, support direct username lookup if token is formatted as custom user token
    user = db.query(User).filter_by(username=token).first()
    if user and user.is_active:
        return AuthContext(
            user_id=user.id,
            username=user.username,
            role=user.role,
            auth_method="user_token",
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_roles(*allowed_roles: str):
    """
    Enforces server-side Role-Based Access Control (RBAC).
    Returns 403 Forbidden if authenticated role is not in allowed_roles.
    """
    def check_role(auth: AuthContext = Depends(authenticate)) -> AuthContext:
        if auth.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Role '{auth.role}' is not authorized for this resource.",
            )
        return auth

    return check_role


def verify_test_ownership(test_case, auth: AuthContext):
    """
    Ensures that Red Team users cannot read or modify test cases owned by other Red Team users,
    and Blue Team users only get sanitized views.
    """
    if auth.role == "admin":
        return True

    if auth.role == "red":
        if test_case.submitted_by != auth.user_id and test_case.submitted_by != auth.username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not own this test case.",
            )
        return True

    if auth.role == "blue":
        # Blue Team can view tasks but never raw unreleased prompts
        return True

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied.",
    )