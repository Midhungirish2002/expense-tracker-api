import jwt
from django.conf import settings
from datetime import datetime, timedelta

ALGORITHM = "HS256"
ACCESS_LIFETIME = timedelta(minutes=60)
REFRESH_LIFETIME = timedelta(days=7)

def create_jwt_token(user_id, token_type="access"):
    now = datetime.utcnow()
    exp = now + (ACCESS_LIFETIME if token_type == "access" else REFRESH_LIFETIME)
    payload = {"user_id": user_id, "type": token_type, "iat": now, "exp": exp}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt_token(token):
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])