from rest_framework import generics, permissions, status, parsers
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from .models import Expense
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer, ExpenseSerializer
from django.db.models import Sum
from django.utils.dateparse import parse_date
from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import create_jwt_token, decode_jwt_token

# Helper to get JWT tokens for a user
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Register user
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.views import APIView
from .serializers import RegisterSerializer, UserSerializer
from .utils import create_jwt_token, decode_jwt_token
from django.contrib.auth.models import User

# Register
class RegisterUser(APIView):
    permission_classes = []
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        access = create_jwt_token(user.id, token_type="access")
        refresh = create_jwt_token(user.id, token_type="refresh")
        return Response({"message":"User created","id":user.id,"username":user.username,"access":access,"refresh":refresh}, status=201)

# Login
class LoginView(APIView):
    permission_classes = []
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if not user:
            return Response({"detail":"Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        access = create_jwt_token(user.id, token_type="access")
        refresh = create_jwt_token(user.id, token_type="refresh")
        return Response({"id": user.id, "username": user.username, "access": access, "refresh": refresh})

class RefreshTokenView(APIView):
    permission_classes = []
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
class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# CRUD for expenses
class ExpenseListCreateView(generics.ListCreateAPIView):
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Expense.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class ExpenseDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Expense.objects.filter(user=self.request.user)

# Filter expenses by date
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def expenses_by_date(request, date):
    date_obj = parse_date(date)
    expenses = Expense.objects.filter(user=request.user, date=date_obj)
    serializer = ExpenseSerializer(expenses, many=True)
    return Response(serializer.data)

# Filter expenses by category
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def expenses_by_category(request, category):
    expenses = Expense.objects.filter(user=request.user, category=category)
    serializer = ExpenseSerializer(expenses, many=True)
    return Response(serializer.data)

# Total expense for a day
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def total_expense_day(request, date):
    date_obj = parse_date(date)
    total = Expense.objects.filter(user=request.user, date=date_obj).aggregate(total=Sum('amount'))['total'] or 0
    return Response({'date': date, 'total': total})

# Total expense for a month
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def total_expense_month(request, month, year):
    total = Expense.objects.filter(user=request.user, date__year=year, date__month=month).aggregate(total=Sum('amount'))['total'] or 0
    return Response({'month': month, 'year': year, 'total': total})
