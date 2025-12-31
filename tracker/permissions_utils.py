from tracker.models import UserPermission

def has_permission(user, permission_code):
    if user.is_staff:
        return True
    return UserPermission.objects.filter(
        user=user,
        code=permission_code
    ).exists()
