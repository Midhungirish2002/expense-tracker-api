from rest_framework import generics, permissions, status, parsers
from .permissions import IsOwner, IsAdmin, IsAdminOrOwner
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from .models import Expense
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer, ExpenseSerializer
from django.db.models import Sum
from django.utils.dateparse import parse_date
from rest_framework.generics import GenericAPIView
from django.shortcuts import get_object_or_404
from tracker.permissions_utils import has_permission
from tracker.permissions import IsActiveUser

from .utils import create_jwt_token, decode_jwt_token


# Register user
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.views import APIView
from .serializers import RegisterSerializer, UserSerializer
from .utils import create_jwt_token, decode_jwt_token
from django.contrib.auth.models import User

# Register
class RegisterUser(GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]   # override global default
    parser_classes = [parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        access = create_jwt_token(user.id, token_type="access")
        refresh = create_jwt_token(user.id, token_type="refresh")
        return Response({"message":"User created","id":user.id,"username":user.username,"access":access,"refresh":refresh}, status=201)

# Login
from django.contrib.auth import authenticate
from django.contrib.auth.models import User

class LoginView(GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]
    parser_classes = [parsers.JSONParser]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        # 🔍 Check if user exists first
        try:
            user_obj = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # 🔒 BLOCK BANNED USER EXPLICITLY
        if not user_obj.is_active:
            return Response(
                {"detail": "Account disabled by admin"},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 🔑 Authenticate normally
        user = authenticate(username=username, password=password)
        if not user:
            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        access = create_jwt_token(user.id, token_type="access")
        refresh = create_jwt_token(user.id, token_type="refresh")

        return Response({
            "id": user.id,
            "username": user.username,
            "access": access,
            "refresh": refresh,
        })

class RefreshTokenView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"detail":"Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            payload = decode_jwt_token(refresh_token)
        except Exception:
            return Response({"detail":"Invalid or expired refresh token"}, status=status.HTTP_401_UNAUTHORIZED)
        if payload.get("type") != "refresh":
            return Response({"detail":"Invalid token type"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=payload.get("user_id"))
        except User.DoesNotExist:
            return Response({"detail":"User not found"}, status=status.HTTP_404_NOT_FOUND)
        access = create_jwt_token(user.id, token_type="access")
        return Response({"access": access})

# Get / update logged-in user profile
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from rest_framework.exceptions import PermissionDenied
from django.contrib.auth.models import User
from .serializers import UserSerializer


class ProfileView(APIView):
    permission_classes = [
        permissions.IsAuthenticated,
        IsActiveUser,
    ]

    def get(self, request):
        request_user = request.user
        user_id = request.query_params.get("user_id")

        if request_user.is_staff and user_id:
            user = get_object_or_404(User, id=user_id)
            return Response(UserSerializer(user).data)

        return Response(UserSerializer(request_user).data)

    def put(self, request):
        request_user = request.user
        user_id = request.query_params.get("user_id")

        if request_user.is_staff and user_id:
            target_user = get_object_or_404(User, id=user_id)
        elif user_id and str(user_id) != str(request_user.id):
            raise PermissionDenied("access denied")
        else:
            target_user = request_user

        serializer = UserSerializer(
            target_user,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)

# AFTER ProfileView, BEFORE Expense views

class AdminToggleUser(APIView):
    # 🔥 OVERRIDE global IsActiveUser
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if not request.user.is_staff:
            raise PermissionDenied("admin only")

        user_id = request.data.get("user_id")
        is_active = request.data.get("is_active")

        if user_id is None or is_active is None:
            return Response(
                {"detail": "user_id and is_active required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = get_object_or_404(User, id=user_id)
        user.is_active = bool(is_active)
        user.save()

        return Response({
            "user_id": user.id,
            "is_active": user.is_active
        })


# CRUD for expenses

class ExpenseDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Expense.objects.all()
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrOwner]

    def perform_update(self, serializer):
        if not has_permission(self.request.user, "edit_expense"):
            raise PermissionDenied("permission denied")
        serializer.save()

    def perform_destroy(self, instance):
        if not has_permission(self.request.user, "delete_expense"):
            raise PermissionDenied("permission denied")
        instance.delete()

# tracker/views.py
from rest_framework.exceptions import PermissionDenied

class ExpenseListCreateView(generics.ListCreateAPIView):
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        request_user = self.request.user

        # Permission check
        if not has_permission(request_user, "view_expense"):
            raise PermissionDenied("permission denied")

        if request_user.is_staff:
            user_id = self.request.query_params.get("user_id")
            return Expense.objects.filter(user_id=user_id) if user_id else Expense.objects.all()

        return Expense.objects.filter(user=request_user)

    def perform_create(self, serializer):
        request_user = self.request.user

        # Permission check
        if not has_permission(request_user, "create_expense"):
            raise PermissionDenied("permission denied")

        serializer.save(user=request_user)  # ✅ FIX

# Filter expenses by date
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def expenses_by_date(request, date):
    request_user = request.user
    user_id = request.query_params.get("user_id")
    date_obj = parse_date(date)

    # Admin: can access any user
    if request_user.is_staff:
        expenses = Expense.objects.filter(
            user_id=user_id if user_id else request_user.id,
            date=date_obj,
        )
        return Response(ExpenseSerializer(expenses, many=True).data)

    # Normal user: only own data
    if user_id and str(user_id) != str(request_user.id):
        from rest_framework.exceptions import PermissionDenied
        raise PermissionDenied(detail="access denied")

    expenses = Expense.objects.filter(
        user=request_user,
        date=date_obj,
    )
    return Response(ExpenseSerializer(expenses, many=True).data)

# Filter expenses by category
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def expenses_by_category(request, category):
    request_user = request.user
    user_id = request.query_params.get("user_id")

    # Admin: can access any user
    if request_user.is_staff:
        expenses = Expense.objects.filter(
            user_id=user_id if user_id else request_user.id,
            category=category,
        )
        return Response(ExpenseSerializer(expenses, many=True).data)

    # Normal user: only own data
    if user_id and str(user_id) != str(request_user.id):
        from rest_framework.exceptions import PermissionDenied
        raise PermissionDenied(detail="access denied")

    expenses = Expense.objects.filter(
        user=request_user,
        category=category,
    )
    return Response(ExpenseSerializer(expenses, many=True).data)


# Total expense for a day
# Total expense for a day
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def total_expense_day(request, date):
    request_user = request.user
    user_id = request.query_params.get("user_id")

    if request_user.is_staff:
        target_user_id = user_id or request_user.id
    else:
        if user_id and str(user_id) != str(request_user.id):
            raise PermissionDenied("access denied")
        target_user_id = request_user.id

    total = Expense.objects.filter(
        user_id=target_user_id,
        date=parse_date(date),
    ).aggregate(total=Sum("amount"))["total"] or 0

    return Response({"date": date, "total": total})

# Total expense for a month
# Total expense for a month
# tracker/views.py
@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def total_expense_month(request, month, year):
    request_user = request.user
    user_id = request.query_params.get("user_id")

    # Admin override
    if request_user.is_staff:
        target_user_id = user_id or request_user.id
    else:
        if user_id and str(user_id) != str(request_user.id):
            raise PermissionDenied("access denied")
        target_user_id = request_user.id

    total = (
        Expense.objects.filter(
            user_id=target_user_id,
            date__month=month,
            date__year=year,
        )
        .aggregate(total=Sum("amount"))["total"]
        or 0
    )

    return Response({
        "month": month,
        "year": year,
        "total": total
    })
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from django.contrib.auth.models import User
from tracker.models import UserPermission

class UserPermissionView(APIView):
    # 🔥 OVERRIDE global IsActiveUser
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Admin-only check
        if not request.user.is_staff:
            raise PermissionDenied("admin only")

        user_id = request.data.get("user_id")
        permission = request.data.get("permission")

        if not user_id or not permission:
            return Response(
                {"detail": "user_id and permission required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = get_object_or_404(User, id=user_id)

        UserPermission.objects.get_or_create(
            user=user,
            code=permission
        )

        return Response({"detail": "permission granted"})

    def delete(self, request):
        if not request.user.is_staff:
            raise PermissionDenied("admin only")

        user_id = request.data.get("user_id")
        permission = request.data.get("permission")

        UserPermission.objects.filter(
            user_id=user_id,
            code=permission
        ).delete()

        return Response({"detail": "permission revoked"})
class DebugWhoAmI(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({
            "username": request.user.username,
            "is_staff": request.user.is_staff,
            "is_active": request.user.is_active,
            "is_superuser": request.user.is_superuser,
        })
