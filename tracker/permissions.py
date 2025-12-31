from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied


class IsOwner(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to access/edit it.
    Assumes the model instance has a `user` attribute.
    """
    def has_object_permission(self, request, view, obj):
        return getattr(obj, "user", None) == request.user


class IsAdmin(permissions.BasePermission):
    """Static permission: only allow staff users."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_staff)
from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied


class IsAdminOrOwner(BasePermission):
    """
    Admin: full access
    User: access only own objects
    """

    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True

        if getattr(obj, "user", None) == request.user:
            return True

        raise PermissionDenied("access denied")
class IsActiveUser(BasePermission):
    message = "User account is disabled"

    def has_permission(self, request, view):
        if request.user and request.user.is_staff:
            return True  # 👈 ADMIN BYPASS

        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_active
        )
