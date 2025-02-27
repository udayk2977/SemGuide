import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ObjectDoesNotExist  
from django.http import JsonResponse
from django.views.decorators.http import require_POST

from rest_framework import generics, status
from rest_framework.generics import CreateAPIView
from rest_framework.authentication import BaseAuthentication
from rest_framework.decorators import api_view, permission_classes
from rest_framework.mixins import CreateModelMixin
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken

from .models import (
    User, Feedback, LoginSession, Semester, Subject, Document, Link
)
from .serializers import (
    UserSerializer, LoginSerializer, FeedbackSerializer, 
    UserUpdateSerializer, UserprofileSerializer, 
    SemesterSerializer, SubjectSerializer, DocumentSerializer, 
    LinkSerializer, SubjectNameSerializer
)


class GetSubjectIDByName(generics.CreateAPIView):
    serializer_class = SubjectNameSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        subject_name = serializer.validated_data.get('name')
        
        try:
            subject = Subject.objects.get(name=subject_name)
            return Response({'id': subject.id}, status=status.HTTP_200_OK)
        except Subject.DoesNotExist:
            return Response({'error': 'Subject not found'}, status=status.HTTP_404_NOT_FOUND)

class SemesterListCreate(generics.ListCreateAPIView):
    queryset = Semester.objects.all()
    serializer_class = SemesterSerializer

class SemesterRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    queryset = Semester.objects.all()
    serializer_class = SemesterSerializer
class SubjectRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = SubjectSerializer

    def get_queryset(self):
        subject_id = self.kwargs['subject_id']
        return Subject.objects.filter(subject_id=subject_id)

class DocumentRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DocumentSerializer

    def get_queryset(self):
        subject_id = self.kwargs['subject_id']
        return Document.objects.filter(subject_id=subject_id)

class LinkRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = LinkSerializer

    def get_queryset(self):
        subject_id = self.kwargs['subject_id']
        return Link.objects.filter(subject_id=subject_id)

class SubjectListCreate(generics.ListCreateAPIView):
    queryset = Subject.objects.all()
    serializer_class = SubjectSerializer

class DocumentListCreate(generics.ListCreateAPIView):
    serializer_class = DocumentSerializer

    def get_queryset(self):
        subject_id = self.kwargs['subject_id']
        document_type = self.request.query_params.get('document_type')  
        queryset = Document.objects.filter(subject_id=subject_id)

        if document_type:
            queryset = queryset.filter(document_type=document_type)

        return queryset


class LinkListCreate(generics.ListCreateAPIView):
    serializer_class = LinkSerializer

    def get_queryset(self):
        subject_id = self.kwargs['subject_id']
        return Link.objects.filter(subject_id=subject_id)

class FeedbackCreateAPIView(CreateAPIView):
    serializer_class = FeedbackSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=None)

class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]


class LoginAPIView(APIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token 
        
        is_admin = user.is_superuser  

        response = Response({
            'user_id': user.id,
            'is_admin': is_admin,
            'message': 'Login successful!'
        }, status=status.HTTP_200_OK)

        response.set_cookie(
            key="access_token",
            value=str(access),
            httponly=True,  # Prevents JavaScript access
            secure=True,  # Only send over HTTPS
            samesite="Lax",
            max_age=300  # 5 minutes expiry
        )
        response.set_cookie(
            key="refresh_token",
            value=str(refresh),
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=86400  # 1 day expiry
        )

        return response




class APILogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refresh_token")

        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()  # Blacklist the token
            except Exception:
                return Response({"error": "Invalid refresh token"}, status=400)

        response = Response({"message": "Logged out successfully!"})
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response


class GetUserFromToken(APIView):
    def post(self, request):
        token = request.data.get('token')
        if token:
            user = self.get_user_from_token(token)
            if user:
                serialized_user = UserprofileSerializer(user)
                return Response(serialized_user.data)
            else:
                return Response({'error': 'Invalid or expired token'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'error': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)
    def get_user_from_token(self, token):
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']
            user = User.objects.get(pk=user_id)
            return user
        except jwt.ExpiredSignatureError:
            return None
        except (jwt.InvalidTokenError, ObjectDoesNotExist):
            return None
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_api_view(request):
    user_id = request.user.id
    return Response({'user_id': user_id})

class UserUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [AnonRateThrottle, UserRateThrottle]

    def get(self, request):
        return Response({"message": " within the request limit!"})
    serializer_class = UserUpdateSerializer

    def put(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        current_password = serializer.validated_data['current_password']
        new_password = serializer.validated_data.get('new_password', None)
        confirm_new_password = serializer.validated_data.get('confirm_new_password', None)

        if not check_password(current_password, user.password):
            return Response({'current_password': ['Incorrect password.']}, status=400)

        if new_password != confirm_new_password:
            return Response({'confirm_new_password': ['New passwords do not match.']}, status=400)

        if new_password:
            user.set_password(new_password)
            user.save()
        return Response({'detail': 'User profile updated successfully.'}, status=200)


