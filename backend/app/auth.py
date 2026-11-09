"""账号。E 实现。"""

import threading
from uuid import uuid4

from pwdlib import PasswordHash

from app.errors import FieldError, Forbidden, Unauthenticated, ValidationError
from app.schemas import User

# 密码哈希用 pyproject 里已有的 pwdlib（argon2），不额外加依赖。
_hasher = PasswordHash.recommended()

# 课程项目阶段的进程内存储：
#   _users_by_no  学号 -> 记录（注册、登录按学号查）
#   _users_by_id  用户 id -> 同一条记录（会话还原用）
#   _sessions     会话 id -> 用户 id（Cookie 里只放会话 id，不放 user.id）
# 以后换数据库只改这个文件，函数签名不变。
_users_by_no: dict[str, dict] = {}
_users_by_id: dict[str, dict] = {}
_sessions: dict[str, str] = {}

# 登录失败的统一提示，学号错和密码错必须一字不差（API-AUTH-02）。
_LOGIN_FAILURE = "学号或密码错误"

# 查重和写入必须一步完成：FastAPI 同步路由跑在线程池里，
# 并发注册同一学号时，没有锁会出现两个同学号用户。
_register_lock = threading.Lock()


def register(student_no: str, nickname: str, password: str) -> User:
    """前置：学号未被占用。后置：持久化用户，role=user，密码只存哈希。"""
    with _register_lock:
        if student_no in _users_by_no:
            # 5.14 规定 fields[].code 只能取 required/unknown_enum/too_long/invalid_file；
            # main.py 把 RequestValidationError 里不属于 missing/too_long 的都归为
            # unknown_enum，这里沿用同一口径。需要组长确认（见提交说明）。
            raise ValidationError([FieldError("student_no", "unknown_enum")], "学号已被注册")
        record = {
            "user": User(id=str(uuid4()), student_no=student_no, nickname=nickname, role="user"),
            "password_hash": _hasher.hash(password),
        }
        _users_by_no[student_no] = record
        _users_by_id[record["user"].id] = record
    return record["user"]


def login(student_no: str, password: str) -> User:
    """学号或密码任何一项错都抛同一个 Unauthenticated，不说明是哪一项。"""
    record = _users_by_no.get(student_no)
    if record is None or not _hasher.verify(password, record["password_hash"]):
        raise Unauthenticated(_LOGIN_FAILURE)
    return record["user"]


def start_session(user_id: str) -> str:
    """建会话，返回随机会话 id。Cookie 的值用它，不用 user.id（CON-03）。"""
    session_id = uuid4().hex
    _sessions[session_id] = user_id
    return session_id


def logout(session_id: str) -> None:
    """前置：会话存在。后置：会话删除。"""
    _sessions.pop(session_id, None)


def current_user(session_id: str) -> User:
    """前置：Cookie 非空。会话不存在或已过期按未登录处理。"""
    user_id = _sessions.get(session_id)
    if user_id is None:
        raise Unauthenticated()
    return _users_by_id[user_id]["user"]


def require_admin(user: User) -> None:
    """role 不是 admin 直接拒绝（CON-04：权限只认服务端数据）。"""
    if user.role != "admin":
        raise Forbidden("需要管理员权限")


def _reset() -> None:
    """清空用户和会话，仅供测试隔离使用。"""
    _users_by_no.clear()
    _users_by_id.clear()
    _sessions.clear()
