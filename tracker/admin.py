from django.contrib import admin

# Register your models here.
from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import Expense, UserPermission
from django.contrib.auth.models import User


@admin.register(Expense)
class ExpenseAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "amount", "category", "date")
    list_filter = ("category", "date")
    search_fields = ("user__username", "category")


@admin.register(UserPermission)
class UserPermissionAdmin(admin.ModelAdmin):
    list_display = ("user", "code")
    list_filter = ("code",)
    search_fields = ("user__username",)


# Optional: extend User admin to see ban status
class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "username", "email", "is_active", "is_staff")
    list_filter = ("is_active", "is_staff")
    search_fields = ("username", "email")


admin.site.unregister(User)
admin.site.register(User, UserAdmin)
