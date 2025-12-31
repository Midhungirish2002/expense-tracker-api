from django.urls import path
from . import views

urlpatterns = [
    path("register/", views.RegisterUser.as_view()),
    path("login/", views.LoginView.as_view()),
    path("profile/", views.ProfileView.as_view()),

    # 🔒 ADMIN: BAN / UNBAN USER
    path(
        "admin/user-status/",
        views.AdminToggleUser.as_view(),
        name="admin-user-status",
    ),
path("debug/me/", views.DebugWhoAmI.as_view()),

    path("expenses/", views.ExpenseListCreateView.as_view()),
    path("expenses/<int:pk>/", views.ExpenseDetailView.as_view()),
    path("expenses/date/<str:date>/", views.expenses_by_date),
    path("expenses/category/<str:category>/", views.expenses_by_category),

    path("totals/day/<str:date>/", views.total_expense_day),
    path("totals/month/<int:month>/<int:year>/", views.total_expense_month),

    path("token/refresh/", views.RefreshTokenView.as_view()),

    # Permissions
    path("admin/permissions/", views.UserPermissionView.as_view()),
]
