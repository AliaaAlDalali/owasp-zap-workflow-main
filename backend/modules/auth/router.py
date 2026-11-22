from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from config import settings
from modules.auth.repository import UserRecord
from modules.auth.schemas import LoginRequest, RegisterRequest, UserResponse
from modules.auth.service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


async def current_user(request: Request) -> UserRecord:
    """Dependency for every signed-in route: resolves the session cookie to a user."""
    token = request.cookies.get(settings.session_cookie_name)
    user = await AuthService().user_for_session(token) if token else None
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="يلزم تسجيل الدخول.")
    return user


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        max_age=settings.session_days * 86400,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, response: Response) -> UserResponse:
    token, user = await AuthService().register(body.email, body.name, body.password, body.organization_name)
    _set_session_cookie(response, token)
    return UserResponse(**user)


@router.post("/login", response_model=UserResponse)
async def login(body: LoginRequest, response: Response) -> UserResponse:
    token, user = await AuthService().login(body.email, body.password)
    _set_session_cookie(response, token)
    return UserResponse(**user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response) -> None:
    token = request.cookies.get(settings.session_cookie_name)
    if token:
        await AuthService().logout(token)
    response.delete_cookie(settings.session_cookie_name, path="/", secure=settings.cookie_secure,
                           httponly=True, samesite="lax")


@router.get("/me", response_model=UserResponse)
async def me(user: UserRecord = Depends(current_user)) -> UserResponse:
    return UserResponse(**user)
