import jwt
from django.conf import settings
from datetime import datetime, timedelta
from django.contrib.auth.models import User
from rest_framework.exceptions import AuthenticationFailed

ALGORITHM = "HS256"
ACCESS_LIFETIME = timedelta(minutes=60)
REFRESH_LIFETIME = timedelta(days=7)

def create_jwt_token(user_id, token_type="access"):
    now = datetime.utcnow()
    exp = now + (ACCESS_LIFETIME if token_type == "access" else REFRESH_LIFETIME)
    payload = {
        "user_id": user_id,
        "type": token_type,
        "iat": now,
        "exp": exp,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_jwt_token(token):
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])

    user_id = payload.get("user_id")

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        raise AuthenticationFailed("User not found")

    # 🔒 GLOBAL BLOCK (THIS IS THE KEY)
    if not user.is_active:
        raise AuthenticationFailed("Account disabled by admin")

    return payload
