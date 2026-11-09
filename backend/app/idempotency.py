"""写操作的 request_id。E 实现。空壳一律视为还没做过。"""

from typing import Any

# 幂等记录表：(user_id, request_id) -> 第一次成功时的响应。
# 注册和登录发生在登录之前，还没有 user.id，路由传入的 user_id 位置是
# student_no（设计说明书 CON-05：注册和登录的幂等范围用 student_no）。
# 课程项目阶段存进程内字典；以后换 SQLite/PostgreSQL 只改这个文件。
_done: dict[tuple[str, str], Any] = {}


def replay_if_done(user_id: str, request_id: str) -> Any | None:
    """写操作开始前调用。这个提交编号已经成功过，就返回当时的响应；否则返回 None。"""
    return _done.get((user_id, request_id))


def save(user_id: str, request_id: str, response: object) -> None:
    """业务成功后保存可重放的响应。调用方必须传不含密码的对象（路由 save 的是 User）。"""
    _done[(user_id, request_id)] = response


def _reset() -> None:
    """清空幂等记录，仅供测试隔离使用。"""
    _done.clear()
