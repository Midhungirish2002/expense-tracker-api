from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.RegisterUser.as_view(), name='api-register'),
    path('login/', views.LoginView.as_view(), name='api-login'),
    path('profile/', views.ProfileView.as_view(), name='api-profile'),
    path('expenses/', views.ExpenseListCreateView.as_view(), name='expenses-list-create'),
    path('expenses/<int:pk>/', views.ExpenseDetailView.as_view(), name='expenses-detail'),
    path('expenses/date/<str:date>/', views.expenses_by_date, name='expenses-by-date'),
    path('expenses/category/<str:category>/', views.expenses_by_category, name='expenses-by-category'),
    path('totals/day/<str:date>/', views.total_expense_day, name='total-day'),
    path('totals/month/<int:month>/<int:year>/', views.total_expense_month, name='total-month'),
]
