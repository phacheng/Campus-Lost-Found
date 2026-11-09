"""账号路由。E 实现会话 Cookie。"""

from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Response

from app.api.deps import SESSION_COOKIE, require_user
from app.auth import login, logout, register, start_session
from app.errors import Unauthenticated
from app.idempotency import replay_if_done, save
from app.schemas import LoginBody, RegisterBody, User

router = APIRouter(tags=["auth"])


def _issue_session(response: Response, user: User) -> None:
    """写入 Cookie clf_session：httponly、samesite=lax、path=/。value 用会话 id，不要用 user.id。"""
    session_id = start_session(user.id)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax", path="/")


@router.post("/auth/register", status_code=201)
def post_register(body: RegisterBody, response: Response) -> User:
    replay = replay_if_done(body.student_no, body.request_id)
    if replay is not None:
        return replay
    user = register(body.student_no, body.nickname, body.password)
    _issue_session(response, user)
    save(body.student_no, body.request_id, user)
    return user


@router.post("/auth/login")
def post_login(body: LoginBody, response: Response) -> User:
    replay = replay_if_done(body.student_no, body.request_id)
    if replay is not None:
        return replay
    user = login(body.student_no, body.password)
    _issue_session(response, user)
    save(body.student_no, body.request_id, user)
    return user


@router.post("/auth/logout", status_code=204)
def post_logout(
    response: Response,
    clf_session: Annotated[str | None, Cookie()] = None,
) -> None:
    if not clf_session:
        raise Unauthenticated()
    logout(clf_session)
    response.delete_cookie(SESSION_COOKIE)


@router.get("/auth/me")
def get_me(user: Annotated[User, Depends(require_user)]) -> User:
    return user
