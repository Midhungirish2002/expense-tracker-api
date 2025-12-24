from rest_framework import generics, permissions, status, parsers
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from .models import Expense
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer, ExpenseSerializer
from django.db.models import Sum
from django.utils.dateparse import parse_date
from rest_framework.authtoken.models import Token
from rest_framework.generics import GenericAPIView

# Register user (supports browsable API form fields)
class RegisterUser(GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = []
    parser_classes = [parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        # create token for immediate use
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'message': 'User created', 'id': user.id, 'username': user.username, 'token': token.key},
                        status=status.HTTP_201_CREATED)


# Login view (accepts separate username/password form fields)
class LoginView(GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = []
    parser_classes = [parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'id': user.id, 'username': user.username}, status=status.HTTP_200_OK)


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

