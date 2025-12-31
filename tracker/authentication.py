from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.contrib.auth import get_user_model
from .utils import decode_jwt_token

User = get_user_model()

class JWTAuthentication(BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request):
        auth = request.headers.get("Authorization")
        if not auth:
            return None
        parts = auth.split()
        if len(parts) != 2 or parts[0] != self.keyword:
            return None
        token = parts[1]
        try:
            payload = decode_jwt_token(token)
        except Exception:
            raise exceptions.AuthenticationFailed("Invalid or expired token")
        if payload.get("type") != "access":
            raise exceptions.AuthenticationFailed("Invalid token type")
        try:
            user = User.objects.get(id=payload.get("user_id"))
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed("User not found")
        return (user, token)
