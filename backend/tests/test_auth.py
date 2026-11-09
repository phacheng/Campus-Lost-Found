"""E1。账号和重复提交。

不用 TestClient（它要额外的 httpx2），直接调用服务函数和路由函数。
HTTP 层的异常翻译由 main.py 负责，不属于 E1 的测试范围。
"""

from concurrent.futures import ThreadPoolExecutor

import pytest
from app import auth, idempotency
from app.api.auth import post_login, post_logout, post_register
from app.api.deps import require_user
from app.errors import Forbidden, Unauthenticated, ValidationError
from app.schemas import LoginBody, RegisterBody
from fastapi import Response
from pydantic import ValidationError as PydanticValidationError

REGISTER = {
    "student_no": "20240001",
    "nickname": "小明",
    "password": "password123",
    "request_id": "req-1",
}


def _body(**overrides: str) -> RegisterBody:
    return RegisterBody(**{**REGISTER, **overrides})


def _login_body(**overrides: str) -> LoginBody:
    data = {
        "student_no": "20240001",
        "password": "password123",
        "request_id": "req-login",
    }
    data.update(overrides)
    return LoginBody(**data)


def _register(**overrides: str):
    """走路由函数，返回 (User, Response)。Response 里带着 Set-Cookie。"""
    response = Response()
    user = post_register(_body(**overrides), response)
    return user, response


def _session_cookie(response: Response) -> str:
    cookie = response.headers.getlist("set-cookie")[0]
    return cookie.split("clf_session=", 1)[1].split(";", 1)[0]


@pytest.fixture(autouse=True)
def _clean_state():
    """每个测试从空存储开始，互不串数据。"""
    auth._reset()
    idempotency._reset()
    yield
    auth._reset()
    idempotency._reset()


def test_register_same_request_id_once() -> None:
    """同一个提交编号注册两次，只有一个用户，返回里没有密码。"""
    first, _ = _register()
    second, _ = _register()

    # 幂等重放：两次返回同一个用户
    assert first.id == second.id
    # 任何响应都不得出现密码（5.3）：User 模型本身没有 password 字段
    assert "password" not in first.model_dump()
    assert "password" not in second.model_dump()
    # 存储里确实只有一个用户，且密码是哈希
    assert len(auth._users_by_no) == 1
    assert auth._users_by_no["20240001"]["password_hash"] != "password123"

    # 幂等键 = student_no（CON-05）：换个 request_id 再注册同一学号，
    # 不是重放，而是学号冲突。code 用 unknown_enum 是组长确认的口径。
    with pytest.raises(ValidationError) as conflict:
        _register(request_id="req-2")
    assert conflict.value.fields[0].name == "student_no"
    assert conflict.value.fields[0].code == "unknown_enum"


def test_login_failure_hides_which_field() -> None:
    """学号或密码错误时登录失败，且不说明是哪一项错。"""
    _register()

    with pytest.raises(Unauthenticated) as wrong_no:
        post_login(_login_body(student_no="20999999"), Response())
    with pytest.raises(Unauthenticated) as wrong_pw:
        post_login(_login_body(password="wrong-password"), Response())

    # 两种失败的提示语必须一字不差（API-AUTH-02），且不区分是哪一项
    assert str(wrong_no.value) == str(wrong_pw.value)
    assert str(wrong_no.value) == "学号或密码错误"

    # 都正确才登录成功
    user = post_login(_login_body(), Response())
    assert user.student_no == "20240001"


def test_register_role_is_user() -> None:
    """注册结果 role 固定为 user，管理员只能来自种子数据（5.2）。"""
    user, _ = _register()
    assert user.role == "user"


def test_logout_clears_session() -> None:
    """退出后会话失效，再取当前用户要被拒绝。"""
    user, response = _register()
    session_id = _session_cookie(response)
    assert require_user(session_id).id == user.id

    post_logout(Response(), session_id)

    with pytest.raises(Unauthenticated):
        require_user(session_id)


def test_unauthenticated_takedown_rejected() -> None:
    """没登录时依赖链第一步就拒绝（VER-01：未登录不能下架）。"""
    with pytest.raises(Unauthenticated):
        require_user(None)


def test_login_replay_returns_first_result() -> None:
    """同一学号同一 request_id 登录两次，返回同一个用户（CON-05）。"""
    _register()
    first = post_login(_login_body(), Response())
    second = post_login(_login_body(), Response())
    assert first.id == second.id


def test_register_field_boundaries() -> None:
    """学号 1–32、密码 8–64 的边界（RegisterBody 的 Field 约束）。"""
    # 学号恰好 32 字符：通过
    _register(student_no="2" * 32)
    # 学号 33 字符：拒绝
    with pytest.raises(PydanticValidationError):
        _body(student_no="2" * 33)
    # 密码 8 位：通过；7 位：拒绝
    _register(student_no="20240002", password="p" * 8, request_id="req-pw8")
    with pytest.raises(PydanticValidationError):
        _body(password="p" * 7)
    # 密码 64 位：通过；65 位：拒绝
    _register(student_no="20240003", password="p" * 64, request_id="req-pw64")
    with pytest.raises(PydanticValidationError):
        _body(password="p" * 65)


def test_password_hash_is_salted() -> None:
    """同一密码注册两个用户，存的是不同的哈希，且哈希里没有明文（5.3）。"""
    _register()
    _register(student_no="20240002", request_id="req-b")
    h1 = auth._users_by_no["20240001"]["password_hash"]
    h2 = auth._users_by_no["20240002"]["password_hash"]
    assert h1 != h2
    assert "password123" not in h1
    assert auth._hasher.verify("password123", h1)
    assert not auth._hasher.verify("password124", h1)


def test_me_with_forged_session_rejected() -> None:
    """伪造的会话 id 取不到用户。"""
    _register()
    with pytest.raises(Unauthenticated):
        require_user("forged-session-id")


def test_logout_without_cookie_rejected() -> None:
    """没带 Cookie 就退出，被拒绝（路由的 Unauthenticated 分支）。"""
    with pytest.raises(Unauthenticated):
        post_logout(Response(), None)


def test_double_logout() -> None:
    """第一次退出成功并删掉会话；之后同一个会话不能再取用户。

    真实客户端第二次退出时 Cookie 已被 delete_cookie 清掉，等同于 clf_session=None，
    路由会按未登录拒绝。
    """
    _, response = _register()
    session_id = _session_cookie(response)

    post_logout(Response(), session_id)
    with pytest.raises(Unauthenticated):
        require_user(session_id)
    # 第二次退出：Cookie 已不在
    with pytest.raises(Unauthenticated):
        post_logout(Response(), None)


def test_two_users_sessions_isolated() -> None:
    """两个用户的会话互不串人。"""
    first, first_resp = _register()
    second, second_resp = _register(student_no="20240002", request_id="req-b")

    assert require_user(_session_cookie(first_resp)).id == first.id
    assert require_user(_session_cookie(second_resp)).id == second.id
    assert first.id != second.id


def test_same_request_id_different_students() -> None:
    """不同学号用同一个 request_id：各建一个用户（CON-05 幂等范围是学号）。"""
    first, _ = _register()
    second, _ = _register(student_no="20240002")
    assert first.id != second.id
    assert len(auth._users_by_no) == 2


def test_concurrent_register_same_student_no_one_user() -> None:
    """并发注册同一学号：查重和写入在锁内，最终只有一个用户。"""
    failures: list[Exception] = []

    def attempt(_i: int) -> None:
        try:
            auth.register("20240001", "并发", "password123")
        except Exception as exc:  # noqa: BLE001 并发下预期是 ValidationError
            failures.append(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(attempt, range(8)))

    assert len(auth._users_by_no) == 1
    assert len(auth._users_by_id) == 1
    assert len(failures) == 7


def test_cookie_flags_and_value() -> None:
    """Set-Cookie 满足 CON-03：HttpOnly、SameSite=lax、Path=/，值不是 user.id。"""
    user, response = _register()
    cookie = response.headers.getlist("set-cookie")[0]
    assert cookie.startswith("clf_session=")
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert "Path=/" in cookie
    value = cookie.split("clf_session=", 1)[1].split(";", 1)[0]
    assert value != user.id
    # 随机会话 id（uuid4().hex 32 位），不是能猜出来的短值
    assert len(value) >= 32


def test_replay_does_not_reissue_cookie() -> None:
    """幂等重放只返回第一次结果，不重发 Set-Cookie（对齐清单第 2 条选 A）。"""
    _, first_resp = _register()
    _, replay_resp = _register()
    assert first_resp.headers.getlist("set-cookie")
    assert not replay_resp.headers.getlist("set-cookie")

    first_login = Response()
    post_login(_login_body(), first_login)
    replay_login = Response()
    post_login(_login_body(), replay_login)
    assert first_login.headers.getlist("set-cookie")
    assert not replay_login.headers.getlist("set-cookie")


def test_require_admin_rejects_normal_user() -> None:
    """普通用户不能过管理员校验，管理员可以（CON-04 权限只认服务端数据）。"""
    user, _ = _register()
    with pytest.raises(Forbidden):
        auth.require_admin(user)
    admin = user.model_copy(update={"role": "admin"})
    auth.require_admin(admin)  # 不抛异常即为通过
