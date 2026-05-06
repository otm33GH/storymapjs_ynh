import hashlib
from flask import session, request, current_app
from .connection import get_user, create_user


def _get_uid(user_string: str) -> str:
    return hashlib.md5(user_string.encode('utf-8')).hexdigest()


def get_remote_user() -> str | None:
    for header in ('X-Remote-User', 'Remote-User', 'HTTP_REMOTE_USER'):
        val = request.headers.get(header) or request.environ.get(header)
        if val:
            return val.strip()
    return None


def login_via_ssowat(db_conn):
    username = get_remote_user()
    if not username:
        return None

    uid = _get_uid('ynh:' + username)

    user = get_user(uid, db=db_conn)
    if not user:
        create_user(uid, username, db=db_conn)
        current_app.logger.info(f"ynh_auth: new user created uid={uid} uname={username}")

    session['uid'] = uid
    return uid


def logout_url() -> str:
    return '/yunohost/sso?action=logout'
