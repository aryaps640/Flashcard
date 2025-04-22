import traceback
from django.shortcuts import redirect, render
from rest_framework import viewsets, status, permissions
from rest_framework import generics
from rest_framework.generics import GenericAPIView 
from rest_framework.permissions import AllowAny, AllowAny
from .models import OneTimePassword, Quiz, ReviewSchedule
from .serializers import PasswordResetRequestSerializer,LogoutUserSerializer, QuizSerializer, ReviewScheduleSerializer,  UserRegisterSerializer, LoginSerializer, SetNewPasswordSerializer, VerifyUserEmailSerializer
from .utils import send_code_to_user
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .models import User
from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view
from django.http import HttpRequest
from rest_framework.decorators import action
from rest_framework.response import Response
from django.http import JsonResponse, Http404
from django.views.decorators.http import require_POST
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from .models import MCQuestion, MCQAnswer, Question, Answer, FillQuestions, FillAnswers, Feedback, CheckStatement, TrueFalse,UploadedImage, Folder,File,Feedback,Tag, User
from .serializers import (
    CheckStatementOnlySerializer, MCQuestionSerializer, MCQAnswerSerializer,
    QuestionSerializer, AnswerSerializer,
    MCQuestionOnlySerializer, MCQAnswerOnlySerializer,
    AnswersOnlySerializer, QuestionsOnlySerializer,
    FillQuestionsSerializer, FillAnswersSerializer,
    FillQuestionOnlySerializer, FillAnswerOnlySerializer,
    CheckStatementSerializer, TrueFalseOnlySerializer, TrueFalseSerializer,
    CreateFolderSerializer, CreateSubfolderSerializer,FolderSerializer,FileSerializer,
    UploadedImageSerializer,FeedbackSerializer,TagSerializer, LoginSerializer)
from django.utils import timezone
from .authentication import CustomJWTAuthentication

from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
import logging

from rest_framework_simplejwt.authentication import JWTAuthentication

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken

class GoogleLoginAPIView(APIView):
    def post(self, request):
        id_token_from_frontend = request.data.get("id_token")
        client_id = request.data.get("client_id")
        client_secret = request.data.get("client_secret")  # Optional, if needed for additional validation

        if not id_token_from_frontend or not client_id:
            return Response({"error": "Both id_token and client_id are required."},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            # Verify the token dynamically using client_id from the request
            idinfo = id_token.verify_oauth2_token(
                id_token_from_frontend,
                google_requests.Request(),
                client_id
            )

            email = idinfo.get("email")
            first_name = idinfo.get("given_name", "")
            last_name = idinfo.get("family_name", "")

            # Create or get the user
            user, created = User.objects.get_or_create(email=email, defaults={
                "username": email,
                "first_name": first_name,
                "last_name": last_name,
                "is_verified": True,  # Mark email as verified
            })

            # Generate tokens
            refresh = RefreshToken.for_user(user)

            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                }
            })

        except ValueError as e:
            return Response({"error": "Invalid ID token", "detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)












def home(request):
    return render(request, 'home.html')

def cards(request):
    return render(request, 'cards.html')

def flashcard(request):
    return render(request, 'flashcard.html')
from django.db.models.functions import Lower
from .permission import IsOwner
from .models import User
# class MCQuestionViewSet(viewsets.ModelViewSet):
    
#     serializer_class = MCQuestionSerializer
#     authentication_classes= [CustomJWTAuthentication]
#     permission_classes = [IsAuthenticated]

    
    
#     def get_queryset(self):
#         user = self.request.user 
#         # Filter questions by the logged-in user
#         return MCQuestion.objects.filter(created_by = user._id)
    
#     def perform_create(self, serializer):
#         """
#         Automatically populate the `created_by` field with the authenticated user's user_id.
#         """
#         # Check if a Question with the same created_by and statement already exists
#         created_by = self.request.user._id
#         statement = serializer.validated_data.get('statement')

#         # If the combination already exists, raise a ValidationError
#         if MCQuestion.objects.filter(created_by=created_by, statement=statement).exists():
#             raise ValidationError("A question with this statement already exists for this user.")
        
#         serializer.save(created_by=self.request.user._id)

from django.db import IntegrityError

class MCQuestionViewSet(viewsets.ModelViewSet):
    serializer_class = MCQuestionSerializer
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return MCQuestion.objects.filter(created_by=user._id)
    
    def perform_create(self, serializer):
        """
        Automatically populate the `created_by` field with the authenticated user's user_id.
        """
        # Check if a Question with the same created_by and statement already exists
        created_by = self.request.user._id
        statement = serializer.validated_data.get('statement')

        # If the combination already exists, raise a ValidationError
        if MCQuestion.objects.filter(created_by=created_by, statement=statement).exists():
            raise ValidationError("A question with this statement already exists for this user.")

        # If not, proceed to save the Question
        serializer.save(created_by=self.request.user._id)

    

    
class MCQAnswerViewSet(viewsets.ModelViewSet):
    queryset = MCQAnswer.objects.all()
    serializer_class = MCQAnswerSerializer
    authentication_classes= [CustomJWTAuthentication]
    permission_classes = [AllowAny]

    

    @action(detail=False, methods=['get'])
    def get_answers(self, request):
        answers = MCQAnswer.objects.all()
        serializer = MCQAnswerOnlySerializer(answers, many=True)
        return Response(serializer.data)
    
    def perform_create(self, serializer):
        question_id = self.request.data.get('question_id')  # Ensure you get the correct question_id
        if question_id:
            serializer.save(question_id=question_id)
        else:
            raise ValidationError('question_id is required.')
    
 


# class QuestionsViewSet(viewsets.ModelViewSet):
    
#     serializer_class = QuestionSerializer
#     authentication_classes= [CustomJWTAuthentication]
#     permission_classes = [IsAuthenticated]

#     def get_queryset(self):
#         # Filter questions based on the authenticated user's email
#         user = self.request.user  # This retrieves the authenticated user
#         return Question.objects.filter(created_by=user._id)
    
#     def perform_create(self, serializer):
#         """
#         Automatically populate the `created_by` field with the authenticated user's user_id.
#         """
#         serializer.save(created_by=self.request.user._id)

    

#     def create(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         return Response(serializer.data, status=status.HTTP_201_CREATED)

#     def update(self, request, *args, **kwargs):
#         instance = self.get_object()
#         serializer = self.get_serializer(instance, data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_update(serializer)
#         return Response(serializer.data)

#     def destroy(self, request, *args, **kwargs):
#         instance = self.get_object()
#         self.perform_destroy(instance)
#         return Response(status=status.HTTP_204_NO_CONTENT)


from django.db import IntegrityError
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.views import exception_handler

class QuestionsViewSet(viewsets.ModelViewSet):
    serializer_class = QuestionSerializer
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Filter questions based on the authenticated user's email
        user = self.request.user  # This retrieves the authenticated user
        return Question.objects.filter(created_by=user._id)

    def perform_create(self, serializer):
        """
        Automatically populate the `created_by` field with the authenticated user's user_id.
        """
        # Check if a Question with the same created_by and statement already exists
        created_by = self.request.user._id
        statement = serializer.validated_data.get('statement')

        # If the combination already exists, raise a ValidationError
        if Question.objects.filter(created_by=created_by, statement=statement).exists():
            raise ValidationError("A question with this statement already exists for this user.")

        # If not, proceed to save the Question
        serializer.save(created_by=self.request.user._id)
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)  # This will handle integrity errors if they occur
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

class AnswersViewSet(viewsets.ModelViewSet):
    
    serializer_class = AnswerSerializer
    authentication_classes= [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Ensure we filter answers based on the authenticated user
        user = self.request.user
        if not user:
            return Answer.objects.none()  # Return no results if user is not authenticated

        # Filter answers by questions created by the logged-in user
        return Answer.objects.filter(question__created_by=user._id)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class FillQuestionViewSet(viewsets.ModelViewSet):
    
    serializer_class = FillQuestionsSerializer
    authentication_classes= [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Filter questions based on the authenticated user's email
        user = self.request.user
        return FillQuestions.objects.filter(created_by=user._id)
    
    def perform_create(self, serializer):
        """
        Automatically populate the `created_by` field with the authenticated user's user_id.
        """
        # Check if a Question with the same created_by and statement already exists
        created_by = self.request.user._id
        statement = serializer.validated_data.get('statement')

        # If the combination already exists, raise a ValidationError
        if FillQuestions.objects.filter(created_by=created_by, statement=statement).exists():
            raise ValidationError("A question with this statement already exists for this user.")
        
        serializer.save(created_by=self.request.user._id)

class FillAnswerViewSet(viewsets.ModelViewSet):
    queryset = FillAnswers.objects.all()
    serializer_class = FillAnswersSerializer
    authentication_classes= [CustomJWTAuthentication]
    permission_classes = [AllowAny]


class CheckStatementViewSet(viewsets.ModelViewSet):
    
    serializer_class = CheckStatementSerializer
    authentication_classes= [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return CheckStatement.objects.filter(created_by = user._id)
    
    def perform_create(self, serializer):
        """
        Automatically populate the `created_by` field with the authenticated user's user_id.
        """
        # Check if a Question with the same created_by and statement already exists
        created_by = self.request.user._id
        statement = serializer.validated_data.get('statement')

        # If the combination already exists, raise a ValidationError
        if CheckStatement.objects.filter(created_by=created_by, statement=statement).exists():
            raise ValidationError("A question with this statement already exists for this user.")
        
        serializer.save(created_by=self.request.user._id)



class TrueFalseViewSet(viewsets.ModelViewSet):
    queryset = TrueFalse.objects.all()
    serializer_class = TrueFalseSerializer
    authentication_classes= [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    

from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError

class FolderViewSet(viewsets.ModelViewSet):
    
    serializer_class = FolderSerializer
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Return only folders belonging to the logged-in user
        return Folder.objects.filter(created_by=self.request.user._id)

    def perform_create(self, serializer):
        # Automatically associate the folder with the logged-in user
        serializer.save(created_by=self.request.user._id)

    def folder_exists_at_level(self, name, parent=None):
        """Check if a folder with the same name exists at the given level."""
        name = name.strip()
        return Folder.objects.filter(name=name, parent=parent).exists()

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        parent_id = data.get('parent')

        # Check if it's a top-level folder (no parent)
        if parent_id is None:
            if self.folder_exists_at_level(data['name'], parent=None):
                raise ValidationError({'error': 'A top-level folder with this name already exists.'})
        else:
            if self.folder_exists_at_level(data['name'], parent_id):
                raise ValidationError({'error': 'A folder with this name already exists under the specified parent.'})

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @action(detail=True, methods=['post'], url_path='create_folder')
    def create_folder(self, request, pk=None):
        parent_folder = self.get_object()
        data = request.data.copy()
        data['parent'] = parent_folder.id
        data['type'] = 'folder'  # Explicitly set type as folder

        if self.folder_exists_at_level(data['name'], parent_folder.id):
            raise ValidationError({'error': 'A folder with this name already exists under the parent folder.'})

        serializer = CreateFolderSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'], url_path='create_subfolder')
    def create_subfolder(self, request, pk=None):
        parent_folder = self.get_object()
        data = request.data.copy()
        data['parent'] = parent_folder.id
        data['type'] = 'subfolder'  # Explicitly set type as subfolder

        if self.folder_exists_at_level(data['name'], parent_folder.id):
            raise ValidationError({'error': 'A subfolder with this name already exists under the parent folder.'})

        serializer = CreateSubfolderSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'], url_path='create_subfolder_in_subfolder')
    def create_subfolder_in_subfolder(self, request, pk=None):
        parent_folder = self.get_object()
        data = request.data.copy()
        data['parent'] = parent_folder.id
        data['type'] = 'subfolder'  # Explicitly set type as subfolder

        if self.folder_exists_at_level(data['name'], parent_folder.id):
            raise ValidationError({'error': 'A subfolder with this name already exists under the parent subfolder.'})

        serializer = CreateSubfolderSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class FileViewSet(viewsets.ModelViewSet):
    
    serializer_class = FileSerializer
    authentication_classes= [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Return only folders belonging to the logged-in user
        return Folder.objects.filter(created_by=self.request.user._id)
    
    def perform_create(self, serializer):
        folder_id = self.request.data.get('folder')  # Get the folder ID from the request data

        # If folder_id is provided, use it; if not, set folder to None (independent file)
        if folder_id:
            folder = Folder.objects.get(id=folder_id)
            serializer.save(created_by=self.request.user._id, folder=folder)  # Save with folder
        else:
            serializer.save(created_by=self.request.user._id)  # Save without folder (independ

@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([AllowAny])
def folder_detail(request, pk):
    try:
        folder = Folder.objects.get(pk=pk)
    except Folder.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    serializer = FolderSerializer(folder)
    return Response(serializer.data)


class DirectoryViewSet(viewsets.ReadOnlyModelViewSet):
    
    serializer_class = FolderSerializer
    authentication_classes= [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Return only folders belonging to the logged-in user
        return Folder.objects.filter(created_by=self.request.user._id)

    def list(self, request, *args, **kwargs):
        parent_id = request.query_params.get('parent', None)
        if parent_id:
            queryset = Folder.objects.filter(parent_id=parent_id, created_by = request.user._id)
        else:
            queryset = Folder.objects.filter(parent=None, created_by = request.user._id)
        serializer = FolderSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def contents(self, request, pk=None):
        folder = self.get_object()
        files = folder.files.all()
        mc_questions = folder.mc_questions.all()
        mcq_answers = folder.mcq_answers.all()
        questions = folder.questions.all()
        answers = folder.answers.all()
        fill_questions = folder.fill_questions.all()
        fill_answers = folder.fill_answers.all()
        check_statements = folder.check_statements.all()
        true_false = folder.true_false.all()

        return Response({
            'files': FileSerializer(files, many=True).data,
            'mc_questions': MCQuestionOnlySerializer(mc_questions, many=True).data,
            'mcq_answers': MCQAnswerOnlySerializer(mcq_answers, many=True).data,
            'questions': QuestionsOnlySerializer(questions, many=True).data,
            'answers': AnswersOnlySerializer(answers, many=True).data,
            'fill_questions': FillQuestionOnlySerializer(fill_questions, many=True).data,
            'fill_answers': FillAnswerOnlySerializer(fill_answers, many=True).data,
            'check_statements': CheckStatementOnlySerializer(check_statements, many=True).data,
            'true_false': TrueFalseOnlySerializer(true_false, many=True).data,
        })

# @authentication_classes([CustomJWTAuthentication])
# @permission_classes([IsAuthenticated])
# def mcq_questions(request):
#     questions = MCQuestion.objects.all()
#     print(request.data.get('email'))
#     serializer = MCQuestionOnlySerializer(questions, many=True)
#     return JsonResponse(serializer.data, safe=False)
# from rest_framework.response import Response
# from rest_framework.decorators import api_view, authentication_classes, permission_classes
# from rest_framework.exceptions import AuthenticationFailed
# from django.http import JsonResponse
# from .models import MCQuestion
# from .serializers import MCQuestionOnlySerializer

# @api_view(['GET'])
# @authentication_classes([CustomJWTAuthentication])
# @permission_classes([IsAuthenticated])
# def mcq_questions(request):
#     user = request.user._id
#     # Handle GET request
#     if request.method == 'GET':
#         # If the user is not authenticated, Django Rest Framework should handle it automatically
#         # Fetch all MCQuestions for the authenticated user
#         questions = MCQuestion.objects.filter(created_by=user)

       

#         # Serialize questions
#         serializer = MCQuestionOnlySerializer(questions, many=True,)

#         # Return serialized data as JSON response
#         return JsonResponse(serializer.data, safe=False)

#     # Handle other HTTP methods if needed
#     return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def mcq_questions(request):
    user = request.user._id  # Assuming user._id is correctly populated
    try:
        questions = MCQuestion.objects.filter(created_by=user)  # Ensure user._id is cast to a string
        serializer = MCQuestionOnlySerializer(questions, many=True)
        return JsonResponse(serializer.data, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



# @authentication_classes([CustomJWTAuthentication])
# @permission_classes([IsAuthenticated])
# def mcq_answers(request):
#     answers = MCQAnswer.objects.all()
#     serializer = MCQAnswerOnlySerializer(answers, many=True)
#     return JsonResponse(serializer.data, safe=False)


from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.status import HTTP_401_UNAUTHORIZED
from .models import MCQAnswer
from .serializers import MCQAnswerOnlySerializer


@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def mcq_answers(request):
    # Verify the user is authenticated
    user = request.user
    if not user:
        return Response({"detail": "Authentication required."}, status=HTTP_401_UNAUTHORIZED)

    # Filter answers by the logged-in user's user_id
    answers = MCQAnswer.objects.filter(question__created_by=user._id)

    # Serialize the filtered data
    serializer = MCQAnswerOnlySerializer(answers, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def FillupQuestions(request):
    # Ensure the user is authenticated
    
    
    # Assuming default User model, use .id or ._id for custom models
    user_id = request.user._id # Or use ._id if you're using a custom User model with _id field
    
    # Filter FillQuestions based on created_by user_id
    questions = FillQuestions.objects.filter(created_by=user_id)
    serializer = FillQuestionOnlySerializer(questions, many=True)
    return JsonResponse(serializer.data, safe=False)



@authentication_classes([CustomJWTAuthentication])
@permission_classes([AllowAny])
def FillupAnswers(request):
    answer = FillAnswers.objects.all()
    serializer = FillAnswerOnlySerializer(answer, many=True)
    return JsonResponse(serializer.data, safe=False)

@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def all_mcq_questions_and_answers(request):
    mcq_questions = MCQuestion.objects.filter(created_by = request.user._id)
    mcq_question_serializer = MCQuestionSerializer(mcq_questions, many=True)
    
    return JsonResponse({'mcq_questions': mcq_question_serializer.data})
@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([AllowAny])
def all_fill_questions_and_answers(request):
    fill_questions = FillQuestions.objects.filter(created_by =request.user._id)
    fill_question_serializer = FillQuestionsSerializer(fill_questions, many=True)
    
    data = {
        'fill_questions_answers': fill_question_serializer.data
    }
    
    return JsonResponse(data)



from rest_framework import generics
from .models import MCQuestion, FillQuestions, TrueFalse, CheckStatement
from .serializers import CombinedQuestionSerializer



class CombinedQuestionsByFolderAPIView(generics.ListAPIView):
    serializer_class = CombinedQuestionSerializer
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        folder_id = self.kwargs['folder_id']  # Get folder_id from URL
        user_id = self.request.user._id  # Fetch the user ID from the authenticated user

        # Filter questions based on the folder_id and created_by (user_id)
        mcqs = MCQuestion.objects.filter(folder_id=folder_id, created_by=user_id)
        fill_questions = FillQuestions.objects.filter(folder_id=folder_id, created_by=user_id)
        true_false = CheckStatement.objects.filter(folder_id=folder_id, created_by=user_id)
        sub = Question.objects.filter(folder_id=folder_id, created_by=user_id)

        # Combine all the filtered results into one list
        combined_queryset = list(mcqs) + list(fill_questions) + list(true_false) + list(sub)
        return combined_queryset





@api_view(['GET', 'POST'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def get_questions_by_subfolder(request, subfolder_id):
    user_id = request.user._id  # Assuming user._id is available, otherwise use request.user.id

    if request.method == 'GET':
        # Filter questions by subfolder_id and the authenticated user's ID (_id)
        mc_questions = MCQuestion.objects.filter(folder_id=subfolder_id, created_by=user_id)
        fill_questions = FillQuestions.objects.filter(folder_id=subfolder_id, created_by=user_id)
        questions = Question.objects.filter(folder_id=subfolder_id, created_by=user_id)
        check_statements = CheckStatement.objects.filter(folder_id=subfolder_id, created_by=user_id)
        uploaded_images = UploadedImage.objects.filter(folder_id=subfolder_id, created_by=user_id)

        # Serialize the filtered questions
        mc_question_serializer = MCQuestionSerializer(mc_questions, many=True)
        fill_question_serializer = FillQuestionsSerializer(fill_questions, many=True)
        questions_serializer = QuestionSerializer(questions, many=True)
        check_statement_serializer = CheckStatementSerializer(check_statements, many=True)
        uploaded_image_serializer = UploadedImageSerializer(uploaded_images, many=True)

        combined_data = []

        # Combine the serialized data with additional information
        for question in mc_question_serializer.data:
            question['question_type'] = 'MCQ'
            question['subfolder_id'] = subfolder_id
            combined_data.append(question)

        for question in fill_question_serializer.data:
            question['question_type'] = 'FIB'
            question['subfolder_id'] = subfolder_id
            combined_data.append(question)

        for question in questions_serializer.data:
            question['question_type'] = 'SUB'
            question['subfolder_id'] = subfolder_id
            combined_data.append(question)

        for question in check_statement_serializer.data:
            question['question_type'] = 'TRUEFALSE'
            question['subfolder_id'] = subfolder_id
            combined_data.append(question)

        for image in uploaded_image_serializer.data:
            image['question_type'] = 'IMAGE'
            image['subfolder_id'] = subfolder_id
            combined_data.append(image)

        return Response(combined_data)

    elif request.method == 'POST':
        data = request.data.copy()
        data['subfolder_id'] = subfolder_id  # Set subfolder_id from URL
        data['created_by'] = user_id  # Set created_by as the current user's ID
        question_type = data.get('question_type')

        if question_type == 'MCQ':
            serializer = MCQuestionSerializer(data=data)
        elif question_type == 'FIB':
            serializer = FillQuestionsSerializer(data=data)
        elif question_type == 'SUB':
            serializer = QuestionSerializer(data=data)
        elif question_type == 'TRUEFALSE':
            serializer = CheckStatementSerializer(data=data)
        elif question_type == 'IMAGE':
            serializer = UploadedImageSerializer(data=data)
        else:
            return Response({"error": "Invalid question type."}, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            question = serializer.save()
            response_data = serializer.data
            response_data['subfolder_id'] = subfolder_id  # Include subfolder_id in the response
            return Response(response_data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])  # Ensure the user is authenticated
def mcq_crud(request, subfolder_id, question_id=None):
    
    # Get the user_id from the JWT token automatically
    user_id = request.user._id  # Ensure user_id is an ObjectId (if necessary)
      # Print user_id to check  

    if request.method == 'GET':
        if question_id:
            try:
                # Fetch the question created by the logged-in user based on user_id
                question = MCQuestion.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
                serializer = MCQuestionSerializer(question)
                return Response(serializer.data)
            except MCQuestion.DoesNotExist:
                return Response({"error": "Data Not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)
        else:
            # Fetch all questions created by the logged-in user in the specified subfolder
            questions = MCQuestion.objects.filter(folder_id=subfolder_id, created_by=user_id)
            serializer = MCQuestionSerializer(questions, many=True)
            return Response(serializer.data)
    


    elif request.method == 'POST':
        user_id = request.user._id
        print(f"Authenticated user ID (from JWT): {user_id}")
    
    # Create a copy of the request data and add the created_by and subfolder_id fields
        data = request.data.copy()
        data['created_by'] = user_id  # Set the created_by field to the logged-in user's user_id
        data['subfolder_id'] = subfolder_id  # Set subfolder_id from URL

    # Check if a Question with the same created_by and statement already exists
        statement = data.get('statement')
        if MCQuestion.objects.filter(created_by=user_id, statement=statement).exists():
            raise ValidationError("A question with this statement already exists for this user.")
    
    # Proceed to create the new question if the validation passes
        serializer = MCQuestionSerializer(data=data, context={'request': request})

        if serializer.is_valid():
         question = serializer.save()
         response_data = serializer.data
         response_data['subfolder_id'] = subfolder_id  # Include subfolder_id in the response
         return Response(response_data, status=status.HTTP_201_CREATED)
    
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    # elif request.method == 'POST':

    #     user_id = request.user._id
    #     print(f"Authenticated user ID (from JWT): {user_id}")
    #     # Create a new question, automatically use the logged-in user's user_id as creator
    #     data = request.data.copy()
    #     data['created_by'] = user_id  # Set the created_by field to the logged-in user's user_id
    #     data['subfolder_id'] = subfolder_id  # Set subfolder_id from URL
    #     serializer = MCQuestionSerializer(data=data,context={'request': request})

    #     if serializer.is_valid():
    #         question = serializer.save()
    #         response_data = serializer.data
    #         response_data['subfolder_id'] = subfolder_id  # Include subfolder_id in the response
    #         return Response(response_data, status=status.HTTP_201_CREATED)

    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'PUT':
        try:
            question = MCQuestion.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
            data = request.data.copy()
            data['subfolder_id'] = subfolder_id  # Ensure subfolder_id remains unchanged
            serializer = MCQuestionSerializer(question, data=data)

            if serializer.is_valid():
                question = serializer.save()
                response_data = serializer.data
                response_data['subfolder_id'] = subfolder_id  # Include subfolder_id in the response
                return Response(response_data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except MCQuestion.DoesNotExist:
            return Response({"error": "Data Not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)

    elif request.method == 'DELETE':
        try:
            question = MCQuestion.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
            question.delete()
            return Response({"message": "Data has been successfully deleted."}, status=status.HTTP_200_OK)
        except MCQuestion.DoesNotExist:
            return Response({"error": "Data Not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)



@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([AllowAny])
def fib_crud(request, subfolder_id, question_id=None):
    user_id = request.user._id  # Extract user_id from the JWT token automatically

    if request.method == 'GET':
        if question_id:
            try:
                question = FillQuestions.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
                serializer = FillQuestionsSerializer(question)
                return Response(serializer.data)
            except FillQuestions.DoesNotExist:
                return Response({"error": "Data Not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            questions = FillQuestions.objects.filter(folder_id=subfolder_id, created_by = user_id)
            serializer = FillQuestionsSerializer(questions, many=True)
            return Response(serializer.data)

    elif request.method == 'POST':
        # Add 'created_by' from the user automatically
        data = request.data.copy()
        data['subfolder_id'] = subfolder_id  # Ensure subfolder_id is included in the request data
        data['created_by'] = user_id  # Automatically set created_by to the logged-in user's user_id
        statement = data.get('statement')
        if FillQuestions.objects.filter(created_by=user_id, statement=statement).exists():
            raise ValidationError("A question with this statement already exists for this user.")
    
        serializer = FillQuestionsSerializer(data=data,context={'request': request})
        
        if serializer.is_valid():
            question = serializer.save()  # Save the new question
            response_data = serializer.data
            response_data['subfolder_id'] = subfolder_id  # Include subfolder_id in the response
            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'PUT':
        try:
            question = FillQuestions.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
            data = request.data.copy()
            data['subfolder_id'] = subfolder_id  # Ensure subfolder_id remains unchanged
            serializer = FillQuestionsSerializer(question, data=data)
            
            if serializer.is_valid():
                question = serializer.save()
                response_data = serializer.data
                response_data['subfolder_id'] = subfolder_id  # Include subfolder_id in the response
                return Response(response_data)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except FillQuestions.DoesNotExist:
            return Response({"error": "Data Not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)

    elif request.method == 'DELETE':
        try:
            question = FillQuestions.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
            question.delete()
            return Response({"message": "Data has been successfully deleted."}, status=status.HTTP_200_OK)
        except FillQuestions.DoesNotExist:
            return Response({"error": "Data Not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([AllowAny])
def sub_crud(request, subfolder_id, question_id=None):
    user_id = request.user._id  # Extract user_id from the JWT token automatically

    if request.method == 'GET':
        if question_id:
            try:
                question = Question.objects.get(pk=question_id, folder_id=subfolder_id, created_by = user_id)
                serializer = QuestionSerializer(question)
                return Response(serializer.data)
            except Question.DoesNotExist:
                return Response({"error": "Data Not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            questions = Question.objects.filter(folder_id=subfolder_id, created_by = user_id)
            serializer = QuestionSerializer(questions, many=True)
            return Response(serializer.data)

    elif request.method == 'POST':
        # Add 'created_by' field to the request data
        data = request.data.copy()
        data['subfolder_id'] = subfolder_id  # Ensure subfolder_id is included in the request data
        data['created_by'] = user_id  # Automatically set created_by to the logged-in user's user_id
        statement = data.get('statement')
        if Question.objects.filter(created_by=user_id, statement=statement).exists():
            raise ValidationError("A question with this statement already exists for this user.")
    
        serializer = QuestionSerializer(data=data,context={'request': request})
        
        if serializer.is_valid():
            question = serializer.save()  # Save the new question
            response_data = serializer.data
            response_data['subfolder_id'] = subfolder_id  # Include subfolder_id in the response
            
            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'PUT':
        try:
            # Ensure that the question belongs to the logged-in user (created_by)
            question = Question.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
            data = request.data.copy()
            data['subfolder_id'] = subfolder_id  # Ensure subfolder_id remains unchanged
            serializer = QuestionSerializer(question, data=data)
            
            if serializer.is_valid():
                question = serializer.save()
                response_data = serializer.data
                response_data['subfolder_id'] = subfolder_id  # Include subfolder_id in the response
                return Response(response_data)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Question.DoesNotExist:
            return Response({"error": "Data Not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)

    elif request.method == 'DELETE':
        try:
            # Ensure that the question belongs to the logged-in user (created_by)
            question = Question.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
            question.delete()
            return Response({"message": "Data has been successfully deleted."}, status=status.HTTP_200_OK)
        except Question.DoesNotExist:
            return Response({"error": "Data Not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)



@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([AllowAny])
def truefalse_crud(request, subfolder_id, question_id=None):
    user_id = request.user._id  # Extract user_id from the JWT token automatically

    if request.method == 'GET':
        if question_id:
            try:
                question = CheckStatement.objects.get(pk=question_id, folder_id=subfolder_id, created_by = user_id)
                serializer = CheckStatementSerializer(question)
                return Response(serializer.data)
            except CheckStatement.DoesNotExist:
                return Response({"error": "Data Not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            questions = CheckStatement.objects.filter(folder_id=subfolder_id, created_by = user_id)
            serializer = CheckStatementSerializer(questions, many=True)
            return Response(serializer.data)

    elif request.method == 'POST':
        # Automatically set 'created_by' to the logged-in user's user_id
        data = request.data.copy()
        data['subfolder_id'] = subfolder_id  # Ensure subfolder_id is included in the request data
        data['created_by'] = user_id  # Set created_by field with user_id
        statement = data.get('statement')
        if CheckStatement.objects.filter(created_by=user_id, statement=statement).exists():
            raise ValidationError("A question with this statement already exists for this user.")
    
        serializer = CheckStatementSerializer(data=data,context={'request': request} )
        
        if serializer.is_valid():
            question = serializer.save()  # Save the new CheckStatement
            response_data = serializer.data
            response_data['subfolder_id'] = subfolder_id  # Include subfolder_id in the response
            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'PUT':
        try:
            # Ensure the question is owned by the logged-in user (created_by)
            question = CheckStatement.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
            data = request.data.copy()
            data['subfolder_id'] = subfolder_id  # Ensure subfolder_id remains unchanged
            serializer = CheckStatementSerializer(question, data=data)
            
            if serializer.is_valid():
                question = serializer.save()  # Save the updated CheckStatement
                response_data = serializer.data
                response_data['subfolder_id'] = subfolder_id  # Include subfolder_id in the response
                return Response(response_data)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except CheckStatement.DoesNotExist:
            return Response({"error": "Data Not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)
        

    elif request.method == 'DELETE':
            try:
                print(f"Attempting to delete question with ID {question_id} in subfolder {subfolder_id} created by {user_id}")
                # Ensure the question is owned by the logged-in user (created_by)
                question = CheckStatement.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
                print(f"Question found: {question}")
                question.delete()
                return Response({"message": "Data has been successfully deleted."}, status=status.HTTP_200_OK)
            except CheckStatement.DoesNotExist:
                return Response({"error": "Data Not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)






class FeedbackViewSet(viewsets.ModelViewSet):
    
    queryset = Feedback.objects.all()
    serializer_class = FeedbackSerializer
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]
    

    

    def create(self, request, *args, **kwargs):

        

        existing_feedback = Feedback.objects.filter(
            flashcard_id=flashcard_id, flashcard_type=flashcard_type, created_by=user_id
        ).first()

        if existing_feedback:
            serializer = self.get_serializer(existing_feedback, data=request.data, partial=True)
        else:
            serializer = self.get_serializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        feedback_instance = serializer.save()

        
        flashcard_id = request.data.get('flashcard_id')
        flashcard_type = request.data.get('flashcard_type')
        feedback_type = request.data.get('feedback')
        user_id = str(request.user._id)
        
        
        logger.info(f"Received feedback request - ID: {flashcard_id}, Type: {flashcard_type}, Feedback: {feedback_type}")
        

        try:
            # Delete old feedback for the same flashcard_id and flashcard_type
            f1 = Feedback.objects.filter(flashcard_id=flashcard_id, flashcard_type=flashcard_type, created_by=user_id)
            deleted_count, _ = f1.delete()  # Ensure deletion
            print(f"Deleted {deleted_count} old feedback entries.")

            # Create new feedback
            data = request.data.copy()
            data['created_by'] = user_id
            data['created_at'] = now().isoformat()  # Convert datetime to ISO format
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            feedback_instance = serializer.save()

            # Handle review schedule
            schedule, created = ReviewSchedule.objects.get_or_create(
                flashcard_id=flashcard_id,
                flashcard_type=flashcard_type,
                created_by=user_id,
                defaults={'next_review_date': timezone.now()}
            )
            schedule.set_next_review_date(feedback_type)

            return Response({
                "feedback": serializer.data,
                "review_schedule": {
                    "next_review": schedule.next_review_date,
                    "review_status": schedule.get_review_status()
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error creating feedback: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

from django.db.models import Case, When


class ReviewFlashcardsView(APIView):
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Get user ID from request
            user_id = str(request.user._id)
            now = timezone.now()  # Changed from _id to id
            
            # Get due flashcards
            due_reviews = ReviewSchedule.objects.filter(
                created_by=user_id,
                next_review_date__lte=timezone.now()
            ).order_by('next_review_date')
            
            flashcards_data = []
            for schedule in due_reviews:
                flashcard_model = self.get_flashcard_model(schedule.flashcard_type)
                if flashcard_model:
                    try:
                        flashcard = flashcard_model.objects.get(
                            id=schedule.flashcard_id,
                            created_by=user_id  # Changed from _id to id
                        )
                        serializer = self.get_flashcard_serializer(schedule.flashcard_type, flashcard)
                        if serializer:
                            review_status = schedule.get_review_status()
                            
                            # Get the latest feedback for this flashcard
                            latest_feedback = Feedback.objects.filter(
                                flashcard_id=schedule.flashcard_id,
                                flashcard_type=schedule.flashcard_type
                            ).order_by('-created_at').first()

                            flashcard_data = {
                                'flashcard': serializer.data,
                                'review_info': review_status,
                                'latest_feedback': FeedbackSerializer(latest_feedback).data if latest_feedback else None
                            }
                            flashcards_data.append(flashcard_data)
                            print(f"Added flashcard to response: {schedule.flashcard_id}")
                    except flashcard_model.DoesNotExist:
                        print(f"Flashcard not found: {schedule.flashcard_id}")
                        continue

            return Response({
                "total_flashcards": len(flashcards_data),
                "current_time": now,
                "flashcards": flashcards_data
            })

        except Exception as e:
            print(f"Error in get: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_flashcard_model(self, flashcard_type):
        """Get the appropriate flashcard model based on type"""
        model_mapping = {
            'MCQ': MCQuestion,
            'FIB': FillQuestions,
            'SUB': Question,
            'TRUEFALSE': CheckStatement,
        }
        return model_mapping.get(flashcard_type)
    
    def get_flashcard_serializer(self, flashcard_type, flashcard):
        """Get the appropriate serializer based on flashcard type"""
        serializer_mapping = {
            'MCQ': MCQuestionSerializer,
            'FIB': FillQuestionsSerializer,
            'SUB': QuestionSerializer,
            'TRUEFALSE': CheckStatementSerializer,
        }
        serializer_class = serializer_mapping.get(flashcard_type)
        if serializer_class:
            return serializer_class(flashcard)
        return None
    # ... rest of your view methods remain the same ...
class AllReviewFlashcardsView(APIView):
    """
    This view will return all flashcards from the ReviewSchedule collection
    without filtering by next_review_date.
    """
    authentication_classes= [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]  # Modify this to restrict permissions if needed.

    def get_flashcard_model(self, flashcard_type):
        """
        Returns the appropriate model class based on the flashcard type.
        """
        models_mapping = {
            'MCQ': MCQuestion,
            'FIB': FillQuestions,
            'SUB': Question,
            'TRUEFALSE': CheckStatement,
        }
        return models_mapping.get(flashcard_type)

    def get_flashcard_serializer(self, flashcard_type, flashcard):
        """
        Returns the appropriate serializer class for the flashcard type.
        """
        serializers_mapping = {
            'MCQ': MCQuestionSerializer,
            'FIB': FillQuestionsSerializer,
            'SUB': QuestionSerializer,
            'TRUEFALSE': CheckStatementSerializer,
        }
        serializer_class = serializers_mapping.get(flashcard_type)
        if serializer_class:
            return serializer_class(flashcard)
        return None

    def get(self, request):
        """
        Retrieves all flashcards for review from the ReviewSchedule collection.
        """
        all_flashcards = ReviewSchedule.objects.all()  # Fetch all records
        flashcards_data = []

        for schedule in all_flashcards:
            # Determine which flashcard model to use based on the flashcard_type
            flashcard_model = self.get_flashcard_model(schedule.flashcard_type)
            if flashcard_model:
                try:
                    # Retrieve flashcard using the stored flashcard_id
                    flashcard = flashcard_model.objects.get(id=schedule.flashcard_id)
                    serializer = self.get_flashcard_serializer(schedule.flashcard_type, flashcard)
                    if serializer:
                        flashcards_data.append(serializer.data)
                except flashcard_model.DoesNotExist:
                    continue  # Skip if the flashcard does not exist

        # Return the flashcards data in the response
        return Response(flashcards_data, status=status.HTTP_200_OK)

class ReviewFlashcardsBySubfolderView(APIView):
    """
    This view will return flashcards for review based on the subfolder.
    Example URL: /review-flashcards/subfolder/{subfolder-id}/
    """
    authentication_classes= [CustomJWTAuthentication]
    permission_classes = [AllowAny]

    def get_flashcard_model(self, flashcard_type):
        # Map flashcard types to models
        models_mapping = {
            'MCQ': MCQuestion,
            'FIB': FillQuestions,
            'SUB': Question,
            'TRUEFALSE': CheckStatement,
        }
        return models_mapping.get(flashcard_type)
    
    def get_flashcard_serializer(self, flashcard_type, flashcard):
        # Map flashcard types to serializers
        serializers_mapping = {
            'MCQ': MCQuestionSerializer,
            'FIB': FillQuestionsSerializer,
            'SUB': QuestionSerializer,
            'TRUEFALSE': CheckStatementSerializer,
        }
        serializer_class = serializers_mapping.get(flashcard_type)
        if serializer_class:
            return serializer_class(flashcard)
        return None

    def get(self, request, subfolder_id):
        """
        Retrieve flashcards due for review in the given subfolder.
        """
        # Get the subfolder based on the provided subfolder_id
        subfolder = get_object_or_404(Folder, id=subfolder_id, type='subfolder')

        # Fetch ReviewSchedule entries that are due for review
        due_flashcards = ReviewSchedule.objects.filter(next_review_date__lte=timezone.now())

        flashcards_data = []

        for schedule in due_flashcards:
            # Get the flashcard model based on the flashcard_type
            flashcard_model = self.get_flashcard_model(schedule.flashcard_type)
            if flashcard_model:
                try:
                    # Retrieve flashcards that belong to the specific subfolder
                    flashcard = flashcard_model.objects.get(id=schedule.flashcard_id, folder=subfolder)  # Updated here
                    serializer = self.get_flashcard_serializer(schedule.flashcard_type, flashcard)
                    if serializer:
                        flashcards_data.append(serializer.data)
                except flashcard_model.DoesNotExist:
                    continue  # Skip if the flashcard does not exist

        return Response(flashcards_data, status=status.HTTP_200_OK)


@authentication_classes([CustomJWTAuthentication])
@permission_classes([AllowAny])
def feedback_detail(request, feedback_id):
    feedback_instance = get_object_or_404(Feedback, id=feedback_id)
    
    related_data = None
    related_answer = None

    if feedback_instance.flashcard_type == 'MCQ':
        related_data = get_object_or_404(MCQuestion, id=feedback_instance.flashcard_id)
        related_answer = MCQAnswer.objects.filter(question=related_data)
    elif feedback_instance.flashcard_type == 'FIB':
        related_data = get_object_or_404(FillQuestions, id=feedback_instance.flashcard_id)
        related_answer = get_object_or_404(FillAnswers, question=related_data)
    elif feedback_instance.flashcard_type == 'SUB':
        related_data = get_object_or_404(Question, id=feedback_instance.flashcard_id)
        related_answer = get_object_or_404(Answer, question=related_data)
    elif feedback_instance.flashcard_type == 'TRUEFALSE':
        related_data = get_object_or_404(CheckStatement, id=feedback_instance.flashcard_id)
        related_answer = TrueFalse.objects.filter(statement=related_data)
    # elif feedback_instance.flashcard_type == 'IMAGE':
    #     related_data = get_object_or_404(UploadedImage, id=feedback_instance.flashcard_id)
        

    context = {
        'feedback_instance': feedback_instance,
        'related_data': related_data,
        'related_answer': related_answer,
    }
    return render(request, 'feedback_detail.html', context)

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import MCQuestion, FillQuestions, Question, CheckStatement, Tag, QuizAttempt
from .serializers import MCQuestionSerializer, FillQuestionsSerializer, QuestionSerializer, CheckStatementSerializer, TagSerializer

@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([AllowAny])
def manage_tags(request, subfolder_id, question_type, question_id, tag_id=None):
    # Get the user_id from the JWT token automatically
    user_id = request.user._id  # Ensure user_id is an ObjectId (if necessary)
      # For debugging

    # Mapping question types to their corresponding models and serializers
    question_mapping = {
        'mcq': (MCQuestion, MCQuestionSerializer),
        'fib': (FillQuestions, FillQuestionsSerializer),
        'sub': (Question, QuestionSerializer),
        'truefalse': (CheckStatement, CheckStatementSerializer),
    }

    if question_type.lower() not in question_mapping:
        return Response({"error": "Invalid question type."}, status=status.HTTP_400_BAD_REQUEST)

    model, serializer_class = question_mapping[question_type.lower()]

    if request.method == 'GET':
        try:
            question = model.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
            serializer = serializer_class(question)
            return Response(serializer.data)
        except model.DoesNotExist:
            return Response({"error": "Question not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)

    elif request.method == 'POST':
        try:
            question = model.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
        except model.DoesNotExist:
            return Response({"error": "Question not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)

        tags = set()
        tags_data = request.data.get('tags', [])
        for tag_data in tags_data:
            if isinstance(tag_data, dict) and 'name' in tag_data:
                tag_name = tag_data['name']
                tag, created = Tag.objects.get_or_create(name=tag_name)
                tags.add(tag)
            else:
                return Response({"error": "Invalid tag format."}, status=status.HTTP_400_BAD_REQUEST)

        question.tags.add(*tags)
        return Response({"message": "Tags added successfully."}, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        if not tag_id:
            return Response({"error": "Tag ID is required for updating a tag."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            question = model.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
            tag = Tag.objects.get(pk=tag_id)
        except (model.DoesNotExist, Tag.DoesNotExist):
            return Response({"error": "Question or Tag not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)

        # Get the updated tag data from the request
        tags_data = request.data.get('tags', [])
        if len(tags_data) != 1:
            return Response({"error": "PUT request should include exactly one tag to update."}, status=status.HTTP_400_BAD_REQUEST)

        tag_data = tags_data[0]
        if not isinstance(tag_data, dict) or 'name' not in tag_data:
            return Response({"error": "Invalid tag format."}, status=status.HTTP_400_BAD_REQUEST)

        tag_name = tag_data['name']
        tag.name = tag_name
        tag.save()

        # Return the updated tag in the response
        return Response({"message": "Tag updated successfully.", "tag": TagSerializer(tag).data}, status=status.HTTP_200_OK)

    elif request.method == 'DELETE':
        if not tag_id:
            return Response({"error": "Tag ID is required for deleting a tag."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            question = model.objects.get(pk=question_id, folder_id=subfolder_id, created_by=user_id)
            tag = Tag.objects.get(pk=tag_id)
        except (model.DoesNotExist, Tag.DoesNotExist):
            return Response({"error": "Question or Tag not found or not created by the logged-in user."}, status=status.HTTP_404_NOT_FOUND)

        question.tags.remove(tag)
        return Response({"message": "Tag removed successfully."}, status=status.HTTP_200_OK)


class QuestionFeedbackView(APIView):
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_question_model(self, question_type):
        model_mapping = {
            'MCQ': MCQuestion,
            'FIB': FillQuestions,
            'SUB': Question,
            'TRUEFALSE': CheckStatement,
        }
        return model_mapping.get(question_type)

    def get(self, request, subfolder_id, question_type, question_id):
        try:
            # First check if user is authenticated
            if not request.user.is_authenticated:
                return Response(
                    {"error": "Authentication required"},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Get the folder
            folder = get_object_or_404(Folder, id=subfolder_id)
            
            # Get the appropriate question model
            question_model = self.get_question_model(question_type)
            if not question_model:
                return Response(
                    {"error": "Invalid question type"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get the question
            question = get_object_or_404(
                question_model, 
                id=question_id, 
                folder=folder, 
                created_by=request.user._id
            )

            # Get feedbacks for this question
            feedbacks = Feedback.objects.filter(
                flashcard_id=str(question_id),
                flashcard_type=question_type
            ).order_by('-created_at')

            # Serialize the feedbacks
            feedback_serializer = FeedbackSerializer(feedbacks, many=True)

            return Response({
                'question_id': question_id,
                'question_type': question_type,
                'feedbacks': feedback_serializer.data
            })

        except Exception as e:
            print(f"Error in QuestionFeedbackView: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request, subfolder_id, question_type, question_id):
        if not request.user.is_authenticated:
            return Response({"detail": "Authentication required."}, status=status.HTTP_401_UNAUTHORIZED)

        user_id = str(request.user._id)  # Use '_id' instead of 'id'
        question_type = question_type.upper()

        # Validate question type
        if question_type not in ['MCQ', 'FIB', 'SUB', 'TRUEFALSE']:
            return Response({"detail": "Invalid question type."}, status=status.HTTP_400_BAD_REQUEST)

        # Get the subfolder
        folder = get_object_or_404(Folder, id=subfolder_id)

        # Get the question
        if question_type == 'MCQ':
            question_model = MCQuestion
            question_serializer_class = MCQuestionSerializer
        elif question_type == 'FIB':
            question_model = FillQuestions
            question_serializer_class = FillQuestionsSerializer
        elif question_type == 'SUB':
            question_model = Question
            question_serializer_class = QuestionSerializer
        elif question_type == 'TRUEFALSE':
            question_model = CheckStatement
            question_serializer_class = CheckStatementSerializer
        else:
            return Response({"detail": "Invalid question type."}, status=status.HTTP_400_BAD_REQUEST)

        question = get_object_or_404(question_model, id=question_id, folder=folder)

        # Ensure the question was created by the authenticated user
        if str(question.created_by) != user_id:
            return Response({"detail": "You do not have permission to add feedback to this question."}, status=status.HTTP_403_FORBIDDEN)

        # Create feedback
        feedback_data = request.data.copy()
        feedback_data['flashcard_type'] = question_type
        feedback_data['flashcard_id'] = question_id
        feedback_data['created_by'] = user_id

        feedback_serializer = FeedbackSerializer(data=feedback_data)
        if feedback_serializer.is_valid():
            feedback_serializer.save()
        else:
            return Response(feedback_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Get the feedback for the question
        feedback = Feedback.objects.filter(flashcard_type=question_type, flashcard_id=question_id)
        feedback_serializer = FeedbackSerializer(feedback, many=True)

        # Combine the serialized data
        question_serializer = question_serializer_class(question)
        data = question_serializer.data
        data['feedback'] = feedback_serializer.data

        return Response(data, status=status.HTTP_200_OK)

    def put(self, request, subfolder_id, question_type, question_id):
        question_type = question_type.upper()

        # Validate question type
        if question_type not in ['MCQ', 'FIB', 'SUB', 'TRUEFALSE']:
            return Response({"detail": "Invalid question type."}, status=status.HTTP_400_BAD_REQUEST)

        feedback = get_object_or_404(Feedback, flashcard_type=question_type, flashcard_id=question_id)
        serializer = FeedbackSerializer(feedback, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, subfolder_id, question_type, question_id):
        question_type = question_type.upper()

        # Validate question type
        if question_type not in ['MCQ', 'FIB', 'SUB', 'TRUEFALSE']:
            return Response({"detail": "Invalid question type."}, status=status.HTTP_400_BAD_REQUEST)

        feedback = get_object_or_404(Feedback,flashcard_type=question_type, flashcard_id=question_id)
        feedback.delete()
        return Response({"message": "Data has been successfully deleted."}, status=status.HTTP_200_OK)


from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import UploadedImage, Folder
from .serializers import UploadedImageSerializer

@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([AllowAny])
def manage_uploaded_images(request, subfolder_id, question_id=None):
    if request.method == 'GET':
        if question_id:
            try:
                uploaded_image = UploadedImage.objects.get(pk=question_id, folder_id=subfolder_id, created_by = request.user._id)
                serializer = UploadedImageSerializer(uploaded_image, context={'request': request})
                return Response(serializer.data)
            except UploadedImage.DoesNotExist:
                return Response({"error": "UploadedImage not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            uploaded_images = UploadedImage.objects.filter(folder_id=subfolder_id)
            serializer = UploadedImageSerializer(uploaded_images, many=True, context={'request': request})
            return Response(serializer.data)

    elif request.method == 'POST':
        data = request.data.copy()
        data['folder'] = subfolder_id  # Set folder_id from URL
        data['question_type'] = 'IMAGE'  # Default value for question_type
        data['created_by'] = request.user._id # Default value for created_by
        serializer = UploadedImageSerializer(data=data, context={'request': request})
        if serializer.is_valid():
            uploaded_image = serializer.save()
            response_data = serializer.data
            response_data['folder'] = subfolder_id  # Include folder_id in the response
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'PUT':
        try:
            uploaded_image = UploadedImage.objects.get(pk=question_id, folder_id=subfolder_id)
            data = request.data.copy()
            data['folder'] = subfolder_id  # Ensure folder_id remains unchanged
            data['question_type'] = uploaded_image.question_type  # Preserve existing question_type
            data['created_by'] = request.user._id # Preserve existing created_by
            serializer = UploadedImageSerializer(uploaded_image, data=data, partial=True, context={'request': request})
            if serializer.is_valid():
                updated_image = serializer.save()
                response_data = serializer.data
                response_data['folder'] = subfolder_id  # Include folder_id in the response
                return Response(response_data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except UploadedImage.DoesNotExist:
            return Response({"error": "UploadedImage not found."}, status=status.HTTP_404_NOT_FOUND)

    elif request.method == 'DELETE':
        try:
            uploaded_image = UploadedImage.objects.get(pk=question_id, folder_id=subfolder_id)
            uploaded_image.delete()
            return Response({"message": "UploadedImage has been successfully deleted."}, status=status.HTTP_200_OK)
        except UploadedImage.DoesNotExist:
            return Response({"error": "UploadedImage not found."}, status=status.HTTP_404_NOT_FOUND)
        
from bson import ObjectId
class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        send_code_to_user(user_data['email'])
        return Response({
            'data': user_data,
            'message': 'Thanks for signing up, a passcode has been sent to verify your email.'
        }, status=status.HTTP_201_CREATED)


from datetime import timedelta
from django.utils.timezone import now

class VerifyUserEmail(GenericAPIView):
    serializer_class = VerifyUserEmailSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            passcode = request.data.get('otp')
            user_pass_obj = OneTimePassword.objects.get(code=passcode)

            # Check if the OTP is expired
            if now() > user_pass_obj.created_at + timedelta(minutes=1):
                return Response({'message': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

            user = user_pass_obj.user
            user.is_verified = True
            user.save()

            return Response({
                'message': 'Account email verified successfully'
            }, status=status.HTTP_200_OK)
        except OneTimePassword.DoesNotExist:
            return Response({'message': 'Invalid passcode'}, status=status.HTTP_400_BAD_REQUEST)

class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction
from django.utils.timezone import now
from rest_framework.exceptions import AuthenticationFailed
from .models import UserSession
from .serializers import LoginSerializer
from django.contrib.auth import authenticate
from django.db.models import F, ExpressionWrapper, DurationField

@api_view(['POST'])
@permission_classes([])  # Allow unauthenticated users to log in
@authentication_classes([])  # No authentication required for login
def login_user(request):
    serializer = LoginSerializer(data=request.data, context={'request': request})

    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    validated_data = serializer.validated_data
    email = validated_data['email']
    password = request.data.get('password')

    user = authenticate(request, email=email, password=password)
    if not user:
        return Response({'status': 'error', 'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.is_verified:
        return Response({'status': 'error', 'message': 'Email is not verified'}, status=status.HTTP_403_FORBIDDEN)

    try:
        with transaction.atomic():
            current_time = now()
            user_id = str(user._id)

            # End all active sessions
            UserSession.objects.filter(user_id=user_id, session_status='active').update(
                logout_time=current_time,
                session_status='ended',
                duration=ExpressionWrapper(current_time - F('login_time'), output_field=DurationField())
            )

            # ✅ Create a new session
            new_session = UserSession.objects.create(
                user_id=user_id,
                login_time=current_time,
                session_status='active'
            )

    except Exception as e:
        return Response({'status': 'error', 'message': f"Error managing sessions: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # ✅ Debug session ID before passing it to tokens()
    print(f"Generated Session ID: {new_session.id} (Type: {type(new_session.id)})")
    tokens = user.tokens(session_id=str(new_session.id))  # Ensure it's a string


    return Response({
        'status': 'success',
        'message': 'Login successful',
        'data': {
            'email': user.email,
            'full_name': user.get_full_name(),
            'access_token': tokens['access'],
            'refresh_token': tokens['refresh'],
            'session_id': new_session.id
        }
    }, status=status.HTTP_200_OK)




class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    permission_classes = [AllowAny]  # Allow unauthenticated access

    def post(self, request):
        serializer=self.serializer_class(data=request.data, context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response({'message':'we have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        # return Response({'message':'user with that email does not exist'}, status=status.HTTP_400_BAD_REQUEST)
    
from django.contrib.auth import get_user_model
User = get_user_model()

from bson import ObjectId  # Import ObjectId for MongoDB compatibility

class PasswordResetConfirm(GenericAPIView):
    permission_classes = [AllowAny]  # Allow unauthenticated access

    def get(self, request, uidb64, token):
        try:
            # Decode the UID
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            logger.debug(f"Decoded user ID: {user_id}")  # Log the decoded user ID

            # Convert user_id to ObjectId for MongoDB query
            user = User.objects.get(_id=ObjectId(user_id))

            # Validate the token
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)

            # If valid, return success response
            return Response({
                'success': True,
                'message': 'Token is valid. You can now reset your password.',
                'uidb64': uidb64,
                'token': token
            }, status=status.HTTP_200_OK)

        except (ValueError, TypeError, DjangoUnicodeDecodeError):
            # Handle decoding errors
            logger.error(f"Invalid UID format: {uidb64}")
            return Response({'message': 'Invalid UID format'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            # Handle missing user
            logger.error(f"User does not exist for UID: {uidb64} (Decoded ID: {user_id})")
            return Response({'message': 'User does not exist for the provided UID'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            # Handle unexpected errors
            logger.error(f"Unexpected error: {str(e)}")
            return Response({'message': 'An unexpected error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    permission_classes = [AllowAny]  # Allow unauthenticated access

    def post(self, request, uidb64, token):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            # Decode the UID and fetch the user
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(_id=ObjectId(user_id))

            # Validate the token
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password
            user.set_password(serializer.validated_data['password'])
            user.save()

            return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)

        except (ValueError, TypeError, DjangoUnicodeDecodeError):
            return Response({'message': 'Invalid UID format'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'message': f'An unexpected error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TestingAuthenticatedReq(GenericAPIView):
    permission_classes=[AllowAny]
    permission_classes = [AllowAny]

    def get(self, request):

        data={
            'msg':'its works'
        }
        return Response(data, status=status.HTTP_200_OK)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.utils.timezone import now
from .models import UserSession
from django.db import transaction
import logging
class LogoutApiView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = request.user
            current_time = now()

            active_session = UserSession.objects.filter(
                user_id=str(user._id), session_status='active'  # ✅ Correct
            ).first()

            if not active_session:
                return Response({'status': 'error', 'message': 'No active session found.'}, status=status.HTTP_400_BAD_REQUEST)

            with transaction.atomic():
                active_session.logout_time = current_time
                active_session.session_status = 'ended'
                active_session.duration = current_time - active_session.login_time
                active_session.save()

            response_data = {
                'status': 'success',
                'message': 'Logged out successfully',
                'session_id': active_session.id,
                'login_time': active_session.login_time,
                'logout_time': active_session.logout_time,
                'session_time': str(active_session.duration)
            }
            
            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error during logout: {str(e)}")
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

logger = logging.getLogger(__name__)

User = get_user_model()

def get_user_from_token(user_id):
    logger.debug(f"Fetching user with ID: {user_id}")
    try:
        user = User.objects.get(id=user_id)
        logger.debug(f"User found: {user}")
        return user
    except User.DoesNotExist:
        logger.error(f"No user found with ID: {user_id}")
        return None

@api_view(['POST'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def logout_user(request):
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return Response({"status": "error", "message": "Authorization token missing"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Extract the access token from the Authorization header
        token = auth_header.split(" ")[1]
        decoded_token = AccessToken(token)  # Decode the access token

        # Extract session_id from the token payload
        session_id = decoded_token.get('session_id')  # ✅ Expect session_id as a string
        print(f"Session ID from token: {session_id}")  # Debugging

        if not session_id:
            return Response({"status": "error", "message": "Session ID is missing from the token."}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Do NOT convert to int, since MongoDB stores ObjectId as string
        session_id = str(session_id)  # ✅ Convert to string to match MongoDB format
        print(f"Session ID from token: {session_id} (Type: {type(session_id)})")
        
        session = UserSession.objects.filter(id=session_id, session_status='active').first()
        print(session)  # Debugging
        
        if not session:
            return Response({"status": "error", "message": "No active session found with this session_id."}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Proceed with logging out the session
        session.logout_time = now()
        session.session_status = "ended"
        session.duration = session.logout_time - session.login_time
        session.save()

        # ✅ Blacklist the refresh token (if using Simple JWT blacklisting)
        refresh_token = decoded_token.get('refresh')
        if refresh_token:
            try:
                token_obj = RefreshToken(refresh_token)
                token_obj.blacklist()  # Mark refresh token as invalid
            except Exception:
                pass  # Ignore if blacklisting is not enabled

        # ✅ Prepare response with session details
        session_data = {
            "status": "success",
            "message": "Logged out successfully",
            "session_id": session.id,  # Should be string
            "login_time": session.login_time,
            "logout_time": session.logout_time,
            "session_duration": str(session.duration)  # Convert timedelta to string
        }

        return Response(session_data, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


from datetime import datetime, timedelta
from django.db.models import Count, Q
from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response

logger = logging.getLogger(__name__)

@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def weekly_summary(request):
    try:
        user_id = str(request.user._id)  # Ensure MongoDB compatibility

        # Calculate the past week's date range
        end_date = timezone.now()
        start_date = end_date - timedelta(days=7)

        # Fetch flashcard IDs created by the authenticated user
        mcq_ids = list(MCQuestion.objects.filter(created_by=user_id).values_list('id', flat=True))
        fib_ids = list(FillQuestions.objects.filter(created_by=user_id).values_list('id', flat=True))
        sub_ids = list(Question.objects.filter(created_by=user_id).values_list('id', flat=True))
        tf_ids = list(CheckStatement.objects.filter(created_by=user_id).values_list('id', flat=True))

        # Base feedback query for the user’s flashcards within the past week
        user_feedback_base = Feedback.objects.filter(
            created_at__range=(start_date, end_date),
            created_by=user_id
        ).filter(
            Q(flashcard_type='MCQ', flashcard_id__in=mcq_ids) |
            Q(flashcard_type='FIB', flashcard_id__in=fib_ids) |
            Q(flashcard_type='SUB', flashcard_id__in=sub_ids) |
            Q(flashcard_type='TRUEFALSE', flashcard_id__in=tf_ids)
        )

        # Summarize feedback by type
        feedback_summary = user_feedback_base.values('feedback').annotate(count=Count('id'))

        # Count flashcards by type
        flashcards_by_type = {
            'MCQ': len(mcq_ids),
            'FIB': len(fib_ids),
            'SUB': len(sub_ids),
            'TRUEFALSE': len(tf_ids)
        }

        # Get daily review counts
        daily_reviews = {}
        for feedback in user_feedback_base:
            date_key = feedback.created_at.date().strftime('%Y-%m-%d')
            daily_reviews[date_key] = daily_reviews.get(date_key, 0) + 1

        daily_reviews_list = [{'date': date, 'reviews': count} for date, count in sorted(daily_reviews.items())]

        # Initialize performance metrics for all feedback types
        performance_metrics = {choice[0]: 0 for choice in Feedback.FEEDBACK_CHOICES}

        # Populate performance metrics based on actual feedback counts
        feedback_counts = {item['feedback']: item['count'] for item in feedback_summary}
        for feedback_type in performance_metrics:
            performance_metrics[feedback_type] = feedback_counts.get(feedback_type, 0)

        # Format the response
        summary = {
            'time_period': {
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': end_date.strftime('%Y-%m-%d')
            },
            'total_cards_reviewed': sum(feedback_counts.values()),
            'flashcards_by_type': flashcards_by_type,
            'daily_activity': daily_reviews_list,
            'performance_breakdown': performance_metrics,
            'feedback_distribution': [
                {'feedback_type': item['feedback'], 'count': item['count']}
                for item in feedback_summary
            ]
        }

        return Response(summary, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error in weekly_summary: {str(e)}")
        return Response({"error": "An error occurred while generating the summary."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


logger = logging.getLogger(__name__)

@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def daily_summary(request):
    try:
        # Get the current authenticated user
        user = request.user
        assert isinstance(user, User), "request.user is not an instance of User"
        user_id = str(user._id)  # Convert to string if necessary for MongoDB

        logger.info(f"Authenticated user: {user}, ID: {user_id}")

        # Calculate today's date range
        end_date = timezone.now()
        start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)


        # Get all flashcard IDs created by the user
        mcq_ids = list(MCQuestion.objects.filter(created_by=user_id).values_list('id', flat=True))
        fib_ids = list(FillQuestions.objects.filter(created_by=user_id).values_list('id', flat=True))
        sub_ids = list(Question.objects.filter(created_by=user_id).values_list('id', flat=True))
        tf_ids = list(CheckStatement.objects.filter(created_by=user_id).values_list('id', flat=True))

        logger.info(f"User Flashcards - MCQ: {len(mcq_ids)}, FIB: {len(fib_ids)}, SUB: {len(sub_ids)}, TRUEFALSE: {len(tf_ids)}")

        # Get today's feedback for the authenticated user
        user_feedback_base = Feedback.objects.filter(
            created_by=user_id,  # Ensure only the user's feedback is retrieved
            created_at__range=(start_date, end_date),
        ).filter(
            (Q(flashcard_type='MCQ') & Q(flashcard_id__in=mcq_ids)) |
            (Q(flashcard_type='FIB') & Q(flashcard_id__in=fib_ids)) |
            (Q(flashcard_type='SUB') & Q(flashcard_id__in=sub_ids)) |
            (Q(flashcard_type='TRUEFALSE') & Q(flashcard_id__in=tf_ids))
        )

        logger.info(f"Total feedback entries today: {user_feedback_base.count()}")

        # Get feedback summary
        feedback_summary = user_feedback_base.values('feedback').annotate(count=Count('id'))

        # Count flashcards by type
        flashcards_by_type = {
            'MCQ': len(mcq_ids),
            'FIB': len(fib_ids),
            'SUB': len(sub_ids),
            'TRUEFALSE': len(tf_ids)
        }

        # Get hourly review counts
        hourly_reviews = {}
        for feedback in user_feedback_base:
            hour_key = feedback.created_at.strftime('%H:00')
            hourly_reviews[hour_key] = hourly_reviews.get(hour_key, 0) + 1

        # Initialize performance metrics with zeros for all possible feedback types
        performance_metrics = {choice[0]: 0 for choice in Feedback.FEEDBACK_CHOICES}

        # Update performance metrics based on actual feedback
        feedback_counts = {item['feedback']: item['count'] for item in feedback_summary}
        for feedback_type in performance_metrics:
            if feedback_type in feedback_counts:
                performance_metrics[feedback_type] = feedback_counts[feedback_type]

        return Response({
            'time_period': {
                'date': start_date.date().strftime('%Y-%m-%d'),
            },
            'total_cards_reviewed': sum(feedback_counts.values()),
            'flashcards_by_type': flashcards_by_type,
            'hourly_activity': [
                {'hour': hour, 'reviews': count} for hour, count in sorted(hourly_reviews.items())
            ],
            'performance_metrics': performance_metrics,
            'feedback_distribution': [
                {'feedback_type': item['feedback'], 'count': item['count']} for item in feedback_summary
            ]
        })
        
    except Exception as e:
        logger.error(f"Error in daily_summary: {str(e)}")
        return Response({'error': str(e)}, status=500)


logger = logging.getLogger(__name__)

@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def monthly_summary(request):
    try:
        user_id = str(request.user._id)  # Ensure MongoDB compatibility

        # Define time period (last 30 days)
        end_date = timezone.now()
        start_date = end_date - timedelta(days=30)

        # Fetch flashcard IDs created by the authenticated user
        mcq_ids = list(MCQuestion.objects.filter(created_by=user_id).values_list('id', flat=True))
        fib_ids = list(FillQuestions.objects.filter(created_by=user_id).values_list('id', flat=True))
        sub_ids = list(Question.objects.filter(created_by=user_id).values_list('id', flat=True))
        tf_ids = list(CheckStatement.objects.filter(created_by=user_id).values_list('id', flat=True))

        # Base feedback query for the user’s flashcards within the last 30 days
        user_feedback_base = Feedback.objects.filter(
            created_at__range=(start_date, end_date),
            created_by=user_id
        ).filter(
            Q(flashcard_type='MCQ', flashcard_id__in=mcq_ids) |
            Q(flashcard_type='FIB', flashcard_id__in=fib_ids) |
            Q(flashcard_type='SUB', flashcard_id__in=sub_ids) |
            Q(flashcard_type='TRUEFALSE', flashcard_id__in=tf_ids)
        )

        # Summarize feedback by type
        feedback_summary = user_feedback_base.values('feedback').annotate(count=Count('id'))

        # Count flashcards by type
        flashcards_by_type = {
            'MCQ': len(mcq_ids),
            'FIB': len(fib_ids),
            'SUB': len(sub_ids),
            'TRUEFALSE': len(tf_ids)
        }

        # Aggregate daily review counts
        daily_reviews = {}
        for feedback in user_feedback_base:
            date_key = feedback.created_at.date().strftime('%Y-%m-%d')
            daily_reviews[date_key] = daily_reviews.get(date_key, 0) + 1

        daily_reviews_list = [{'date': date, 'reviews': count} for date, count in sorted(daily_reviews.items())]

        # Calculate weekly averages
        weekly_averages = {}
        for date_str, count in daily_reviews.items():
            date = datetime.strptime(date_str, '%Y-%m-%d')
            week_number = date.strftime('%U')  # Get week number
            if week_number not in weekly_averages:
                weekly_averages[week_number] = {'total': 0, 'days': 0}
            weekly_averages[week_number]['total'] += count
            weekly_averages[week_number]['days'] += 1

        weekly_averages_list = [
            {'week': week, 'average_reviews': round(avg['total'] / avg['days'], 2)}
            for week, avg in weekly_averages.items()
        ]

        # Initialize performance metrics for all feedback types
        performance_metrics = {choice[0]: 0 for choice in Feedback.FEEDBACK_CHOICES}

        # Populate performance metrics based on actual feedback counts
        feedback_counts = {item['feedback']: item['count'] for item in feedback_summary}
        for feedback_type in performance_metrics:
            performance_metrics[feedback_type] = feedback_counts.get(feedback_type, 0)

        # Format the response
        summary = {
            'time_period': {
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': end_date.strftime('%Y-%m-%d')
            },
            'total_cards_reviewed': sum(feedback_counts.values()),
            'flashcards_by_type': flashcards_by_type,
            'daily_activity': daily_reviews_list,
            'weekly_averages': weekly_averages_list,
            'performance_metrics': performance_metrics,
            'feedback_distribution': [
                {'feedback_type': item['feedback'], 'count': item['count']}
                for item in feedback_summary
            ]
        }

        return Response(summary, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error in monthly_summary: {str(e)}")
        return Response({"error": "An error occurred while generating the summary."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




logger = logging.getLogger(__name__)

@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def yearly_summary(request):
    try:
        user_id = str(request.user._id)  # Ensure MongoDB compatibility

        # Define time period (last 365 days)
        end_date = timezone.now()
        start_date = end_date - timedelta(days=365)

        # Fetch flashcard IDs created by the authenticated user
        mcq_ids = list(MCQuestion.objects.filter(created_by=user_id).values_list('id', flat=True))
        fib_ids = list(FillQuestions.objects.filter(created_by=user_id).values_list('id', flat=True))
        sub_ids = list(Question.objects.filter(created_by=user_id).values_list('id', flat=True))
        tf_ids = list(CheckStatement.objects.filter(created_by=user_id).values_list('id', flat=True))

        # Base feedback query for the user’s flashcards within the last 365 days
        user_feedback_base = Feedback.objects.filter(
            created_at__range=(start_date, end_date),
            created_by=user_id
        ).filter(
            Q(flashcard_type='MCQ', flashcard_id__in=mcq_ids) |
            Q(flashcard_type='FIB', flashcard_id__in=fib_ids) |
            Q(flashcard_type='SUB', flashcard_id__in=sub_ids) |
            Q(flashcard_type='TRUEFALSE', flashcard_id__in=tf_ids)
        )

        # Summarize feedback by type
        feedback_summary = user_feedback_base.values('feedback').annotate(count=Count('id'))

        # Count flashcards by type
        flashcards_by_type = {
            'MCQ': len(mcq_ids),
            'FIB': len(fib_ids),
            'SUB': len(sub_ids),
            'TRUEFALSE': len(tf_ids)
        }

        # Aggregate monthly review counts and performance metrics
        monthly_data = {}
        for feedback in user_feedback_base:
            month_key = feedback.created_at.strftime('%Y-%m')
            
            if month_key not in monthly_data:
                monthly_data[month_key] = {
                    'total_reviews': 0,
                    'performance_metrics': {
                        choice[0]: 0 for choice in Feedback.FEEDBACK_CHOICES
                    }
                }
            
            monthly_data[month_key]['total_reviews'] += 1
            monthly_data[month_key]['performance_metrics'][feedback.feedback] += 1

        monthly_summary = [
            {
                'month': month,
                'total_reviews': data['total_reviews'],
                'performance_metrics': data['performance_metrics']
            }
            for month, data in sorted(monthly_data.items())
        ]

        # Calculate overall performance metrics for the year
        performance_metrics = {
            choice[0]: 0 for choice in Feedback.FEEDBACK_CHOICES
        }

        # Update performance metrics based on actual feedback
        feedback_counts = {item['feedback']: item['count'] for item in feedback_summary}
        for feedback_type in performance_metrics:
            performance_metrics[feedback_type] = feedback_counts.get(feedback_type, 0)

        # Format the response
        summary = {
            'time_period': {
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': end_date.strftime('%Y-%m-%d')
            },
            'total_cards_reviewed': sum(feedback_counts.values()),
            'flashcards_by_type': flashcards_by_type,
            'monthly_summary': monthly_summary,
            'overall_performance_metrics': performance_metrics,
            'feedback_distribution': [
                {'feedback_type': item['feedback'], 'count': item['count']}
                for item in feedback_summary
            ]
        }

        return Response(summary, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error in yearly_summary: {str(e)}")
        return Response({"error": "An error occurred while generating the summary."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def clear_sessions(request):
    try:
        user_id = str(request.user._id)
        UserSession.objects.filter(user_id=user_id).delete()
        return Response({
            'status': 'success',
            'message': 'All sessions cleared successfully'
        })
    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import UserSession

# @api_view(['GET'])
# @authentication_classes([CustomJWTAuthentication])  # Add this line
# @permission_classes([IsAuthenticated])
# def get_user_sessions(request):
#     try:
#         user_id = str(request.user._id)
#         sessions = UserSession.objects.filter(user_id=user_id).order_by('-login_time')
        
#         session_data = []
#         for session in sessions:
#             data = {
#                 'login_time': session.login_time.strftime("%Y-%m-%d %H:%M:%S"),
#                 'logout_time': session.logout_time.strftime("%Y-%m-%d %H:%M:%S") if session.logout_time else None,
#                 'duration': str(session.duration) if session.duration else None,
#                 'status': session.session_status
#             }
#             session_data.append(data)
        
#         return Response({
#             'status': 'success',
#             'sessions': session_data
#         })
#     except Exception as e:
#         return Response({
#             'status': 'error',
#             'message': str(e)
#         }, status=status.HTTP_400_BAD_REQUEST)


# @api_view(['GET'])
# @authentication_classes([CustomJWTAuthentication])  # Add this line
# @permission_classes([IsAuthenticated])
# def get_user_sessions(request):
#     try:
#         user_id = str(request.user._id)
#         print(f"Getting sessions for user: {user_id}")
        
#         # First cleanup any inconsistent sessions
#         cleanup_user_sessions(user_id)
        
#         # Get all sessions, ordered by newest first
#         sessions = UserSession.objects.filter(
#             user_id=user_id,
#             login_time__isnull=False  # Ensure login_time exists
#         ).order_by('-login_time')
        
#         print(f"Found {sessions.count()} total sessions")

#         session_data = []
#         seen_login_times = set()  # Track unique login times
#         active_session_added = False  # Track if we've added an active session
        
#         for session in sessions:
#             login_time_str = session.login_time.strftime("%Y-%m-%d %H:%M:%S")
            
#             # Skip if we've seen this login time before
#             if login_time_str in seen_login_times:
#                 print(f"Skipping duplicate session with login time: {login_time_str}")
#                 continue
            
#             # If this is an active session and we already added one, skip it
#             if session.session_status == 'active' and active_session_added:
#                 print(f"Skipping additional active session with login time: {login_time_str}")
#                 continue
            
#             seen_login_times.add(login_time_str)
            
#             data = {
#                 'login_time': login_time_str,
#                 'logout_time': session.logout_time.strftime("%Y-%m-%d %H:%M:%S") if session.logout_time else None,
#                 'duration': str(session.duration) if session.duration else None,
#                 'status': session.session_status
#             }
            
#             if session.session_status == 'active':
#                 active_session_added = True
            
#             session_data.append(data)
#             print(f"Added session: {data}")

#         return Response({
#             'status': 'success',
#             'sessions': session_data
#         })
#     except Exception as e:
#         print(f"Error in get_user_sessions: {str(e)}")
#         return Response({
#             'status': 'error',
#             'message': str(e)
#         }, status=status.HTTP_400_BAD_REQUEST)

def cleanup_user_sessions(user_id):
    """Helper function to ensure only one active session exists"""
    try:
        # Get all active sessions ordered by login time (newest first)
        active_sessions = UserSession.objects.filter(
            user_id=user_id,
            session_status='active'
        ).order_by('-login_time')

        count = active_sessions.count()
        if count > 1:
            print(f"Found {count} active sessions, cleaning up...")
            # Keep the newest one active, end all others
            newest = active_sessions.first()
            current_time = timezone.now()
            
            # End all other active sessions
            for session in active_sessions.exclude(id=newest.id):
                # If the session has no logout time, set it to the login time of the newer session
                if not session.logout_time:
                    # If this is a forced logout (user didn't explicitly logout)
                    session.logout_time = newest.login_time
                    session.session_status = 'ended'
                    session.duration = session.logout_time - session.login_time
                    session.save()
                    print(f"Ended session {session.id} with login time: {session.login_time}")

            print("Cleanup complete")
    except Exception as e:
        print(f"Error in cleanup: {str(e)}")

@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])  # Add this line
@permission_classes([IsAuthenticated])
def get_user_sessions(request):
    try:
        user_id = str(request.user._id)
        print(f"Getting sessions for user: {user_id}")

        # Query all sessions, ordered by newest first
        sessions = UserSession.objects.filter(
            user_id=user_id,
            login_time__isnull=False  # Ensure login_time exists
        ).order_by('-login_time')

        print(f"Found {sessions.count()} total sessions")

        session_data = []
        seen_login_times = set()  # Track unique login times
        active_session_found = False  # Ensure only one active session is processed
        
        for session in sessions:
            login_time_str = session.login_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Skip duplicate login times
            if login_time_str in seen_login_times:
                print(f"Skipping duplicate session with login time: {login_time_str}")
                continue

            # Handle active sessions directly
            if session.session_status == 'active':
                if active_session_found:
                    # If an active session already exists, treat this as ended
                    print(f"Marking redundant active session as ended: {login_time_str}")
                    session_data.append({
                        'login_time': login_time_str,
                        'logout_time': None,
                        'duration': None,
                        'status': 'redundant_active'
                    })
                    continue
                else:
                    active_session_found = True

            # Add session to response data
            session_data.append({
                'login_time': login_time_str,
                'logout_time': session.logout_time.strftime("%Y-%m-%d %H:%M:%S") if session.logout_time else None,
                'duration': str(session.duration) if session.duration else None,
                'status': session.session_status
            })
            seen_login_times.add(login_time_str)

        return Response({
            'status': 'success',
            'sessions': session_data
        })
    except Exception as e:
        print(f"Error in get_user_sessions: {str(e)}")
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)



#Quiz
class QuizViewSet(viewsets.ModelViewSet):
    queryset = Quiz.objects.all()
    serializer_class = QuizSerializer
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Allow users to access only their quizzes
        return self.queryset.filter(user=self.request.user)

    def perform_create(self, serializer):
        # Logic for starting a quiz
        folder_id = self.request.data.get('folder')
        folder = Folder.objects.get(id=folder_id)
        total_questions = folder.mc_questions.count() + folder.fill_questions.count() + folder.check_statements.count() + folder.questions.count()
        
        # Get the passing percentage from payload or use 35.0
        passing_percentage = self.request.data.get('passing_percentage', 35.0)
        max_attempts = self.request.data.get('max_attempts', None)
        quiz = serializer.save(created_by=self.request.user._id, total_questions=total_questions, 
                               passing_percentage=passing_percentage, max_attempts=max_attempts)

        # Add payload response with quiz ID
        self.request.data['quiz_id'] = quiz.id

@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([AllowAny])
def get_quiz_questions(request, quiz_id):
    quiz = Quiz.objects.get(id=quiz_id)  # Fetch quiz instance
    folder = quiz.folder  # Get associated folder

    # Fetching questions from the folder (use your actual logic for folder-based filtering)
    mcq_questions = MCQuestion.objects.filter(folder=folder)
    truefalse_questions = CheckStatement.objects.filter(folder=folder)
    fillup_questions = FillQuestions.objects.filter(folder=folder)
    subjective_questions = Question.objects.filter(folder=folder)

    # Serializing questions
    mcq_serializer = MCQuestionSerializer(mcq_questions, many=True)
    truefalse_serializer = CheckStatementSerializer(truefalse_questions, many=True)
    fillup_serializer = FillQuestionsSerializer(fillup_questions, many=True)
    subjective_serializer = QuestionSerializer(subjective_questions, many=True)

    # Combining all questions
    all_questions = mcq_serializer.data + truefalse_serializer.data + fillup_serializer.data + subjective_serializer.data

    # Looping through questions and removing the 'correct_answer' field from each
    for question in all_questions:
        question.pop('correct_answer', None)  # Removing the correct answer
        question.pop('explanation', None)
        if question['question_type'] == 'MCQ':
            # Remove 'is_correct' from MCQ answers
            for answer in question.get('answers', []):
                answer.pop('is_correct', None)
        
        if question['question_type'] in ['TRUEFALSE', 'FIB', 'SUB']:
            # Remove 'answers' from Fill and True/False questions
            question.pop('answers', None)
    return Response(all_questions, status=200)


@api_view(['POST'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def submit_quiz_answers(request, quiz_id):
    # Ensure the user is authenticated and get the user ID
    user_id = request.user._id
    print(f"Authenticated user ID: {user_id}")

    # Fetch the quiz for the authenticated user
    quiz = Quiz.objects.get(id=quiz_id, created_by=user_id)

    answers = request.data.get('answers', [])  # List of answers from the user
    correct_answers = 0

    for answer in answers:
        question_id = answer.get('question_id')
        selected_answer = answer.get('selected_answer').strip().lower()
        print(f"Processing question_id: {question_id}, selected_answer: {selected_answer}")  

        # Initialize both string and integer versions
        question_id_str = None
        question_id_int = None

        try:
            # Try to convert to integer
            question_id_int = int(question_id)
            print(f"Using Integer question_id: {question_id_int}")
        except ValueError:
            # If conversion fails, assume it's a string ID
            question_id_str = str(question_id)
            print(f"Using String question_id: {question_id_str}")

        # **MCQ Questions (String-based IDs)**
        if question_id_str:
            mcq = MCQuestion.objects.filter(id=question_id_str).first()
            if mcq:
                mcq_answers = MCQAnswer.objects.filter(question_id=str(mcq.id))
                print(f"MCQuestion Answers: {mcq_answers}")

                correct_mcq_answer = None
                for ans in mcq_answers:
                    if ans.is_correct:
                        print(f"Answer: {ans.answer_text}, is_correct: {ans.is_correct}")
                        correct_mcq_answer = ans.answer_text.strip().lower()
                print(f"Correct Answer In Lower Case: {correct_mcq_answer}")

                if selected_answer == correct_mcq_answer:
                    correct_answers += 1
                    print(f"✅ Correct answer matched for MCQ: {mcq.statement}")

        # **Fill in the Blanks & True/False Questions (Integer-based IDs)**
        if question_id_int is not None:
            fill = FillQuestions.objects.filter(id=question_id_int).first()
            if fill:
                correct_fill_answers = FillAnswers.objects.filter(question=fill)
                if correct_fill_answers.filter(answer__iexact=selected_answer).exists():
                    correct_answers += 1

            truefalse_question = CheckStatement.objects.filter(id=question_id_int).first()
            if truefalse_question:
                correct_tf_answers = TrueFalse.objects.filter(statement=truefalse_question)
                if correct_tf_answers.filter(ans__iexact=selected_answer).exists():
                    correct_answers += 1

            subjective_question = Question.objects.filter(id=question_id_int, question_type="SUB").first()
            if subjective_question:
                correct_sub_answers = Answer.objects.filter(question=subjective_question)
                if correct_sub_answers.filter(answer_text__iexact=selected_answer).exists():
                    correct_answers += 1

    previous_attempts = QuizAttempt.objects.filter(quiz=quiz, user=request.user).count()

    if quiz.max_attempts is not None and previous_attempts >= quiz.max_attempts:
        return Response({"error": "Maximum number of attempts reached."}, status=403)

    attempt_number = previous_attempts + 1        

    
    try:
        attempted_questions = len(answers)
        wrong_answers = attempted_questions - correct_answers
        final_score = correct_answers - wrong_answers
        total_questions = quiz.total_questions
        score_percentage = (final_score / total_questions) * 100 if total_questions else 0
        passing_percentage = quiz.passing_percentage or 35.0
        result = "Pass" if score_percentage >= passing_percentage else "Fail"
        quiz_status = "Completed" if attempted_questions == total_questions else "In Progress"

        quiz_attempt = QuizAttempt.objects.create(
            quiz=quiz,
            user=request.user,
            attempted_questions=attempted_questions,
            total_questions=total_questions,
            correct_answers=correct_answers,
            wrong_answers=wrong_answers,
            final_score=final_score,
            score_percentage=score_percentage,
            passing_percentage=passing_percentage,
            result=result,
            quiz_status=quiz_status,
            started_at=quiz.started_at or timezone.now(),
            ended_at=timezone.now()
        )

    except Exception as e:
        print(f"Error saving quiz attempt: {str(e)}")
        return Response({"error": f"Error saving quiz attempt: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
   

    return Response({
        "quiz_Id": quiz.id,
        "quiz_attempt_id": str(quiz_attempt.id),
        "attempt_number": attempt_number,  # Include attempt number
        "max_attempts": quiz.max_attempts,  # Include max attempts
        "attempted_questions": quiz_attempt.attempted_questions,
        "total_questions": quiz_attempt.total_questions,
        "correct_answers": quiz_attempt.correct_answers,
        "wrong_answers": quiz_attempt.wrong_answers,
        "Final Score": quiz_attempt.final_score,
        "score_percentage": round(quiz_attempt.score_percentage, 2),
        "passing_percentage": quiz_attempt.passing_percentage,
        "result": quiz_attempt.result,
        "quiz_status": quiz_attempt.quiz_status,
        "started_at": quiz_attempt.started_at,
        "ended_at": quiz_attempt.ended_at,
        "folder": quiz.folder.id if quiz.folder else None,
        "user_id": str(quiz_attempt.user._id)
    }, status=200)




@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def get_quiz_result(request, quiz_id):
    """
    Retrieve the result of a quiz for the authenticated user.
    """
    user_id = request.user._id  # Get the authenticated user ID
    
    try:
        # Ensure the quiz belongs to the user
        #quiz = Quiz.objects.get(id=quiz_id, created_by=user_id)
        quiz = Quiz.objects.get(id=quiz_id, created_by=user_id)
        quiz_attempts = QuizAttempt.objects.filter(quiz=quiz, user=request.user).order_by('ended_at')

        if not quiz_attempts:
            return Response({"error": "No attempt found for this quiz."}, status=404)

    except Quiz.DoesNotExist:
        return Response({"error": "Quiz not found or unauthorized access."}, status=status.HTTP_404_NOT_FOUND)


    

    # Prepare the result data for all attempts
    attempts_data = []
    for attempt_number, quiz_attempt in enumerate(quiz_attempts, start=1):
        attempts_data.append({
            "attempt_number": attempt_number,
            "quiz_attempt_id": str(quiz_attempt.id),
            "max_attempts": quiz.max_attempts,
            "attempted_questions": quiz_attempt.attempted_questions,
            "total_questions": quiz_attempt.total_questions,
            "correct_answers": quiz_attempt.correct_answers,
            "wrong_answers": quiz_attempt.wrong_answers,
            "final_score": quiz_attempt.final_score,
            "score_percentage": round(quiz_attempt.score_percentage, 2),
            "passing_percentage": quiz_attempt.passing_percentage,
            "result": quiz_attempt.result,
            "quiz_status": quiz_attempt.quiz_status,
            "started_at": quiz_attempt.started_at,
            "ended_at": quiz_attempt.ended_at
        })

    # Return the result data
    result_data = {
        "quiz_Id": str(quiz.id),
        "folder_Id": str(quiz.folder.id) if quiz.folder else None,
        "user_id": str(request.user._id),
        "total_attempts": len(attempts_data),
        "max_attempts": quiz.max_attempts,  # Include max attempts
        "attempts": attempts_data
    }

    return Response(result_data, status=status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def get_quiz_attempt_result(request, quiz_id, attempt_number):
    """
    Retrieve the result of a specific attempt for a quiz by attempt number.
    """
    user_id = request.user._id  # Get the authenticated user ID

    try:
        # Ensure the quiz belongs to the user
        quiz = Quiz.objects.get(id=quiz_id, created_by=user_id)
        quiz_attempts = QuizAttempt.objects.filter(quiz=quiz, user=request.user).order_by('ended_at')

        if not quiz_attempts.exists():
            return Response({"error": "No attempts found for this quiz."}, status=404)

        # Get the specific attempt by attempt number
        if attempt_number < 1 or attempt_number > quiz_attempts.count():
            return Response({"error": "Invalid attempt number."}, status=400)

        quiz_attempt = quiz_attempts[attempt_number - 1]  # Convert attempt_number to zero-based index

    except Quiz.DoesNotExist:
        return Response({"error": "Quiz not found or unauthorized access."}, status=status.HTTP_404_NOT_FOUND)

    # Prepare the result data for the specific attempt
    result_data = {
        "quiz_Id": str(quiz.id),
        "quiz_attempt_id": str(quiz_attempt.id),
        "attempt_number": attempt_number,
        "max_attempts": quiz.max_attempts,
        "attempted_questions": quiz_attempt.attempted_questions,
        "total_questions": quiz_attempt.total_questions,
        "correct_answers": quiz_attempt.correct_answers,
        "wrong_answers": quiz_attempt.wrong_answers,
        "final_score": quiz_attempt.final_score,
        "score_percentage": round(quiz_attempt.score_percentage, 2),
        "passing_percentage": quiz_attempt.passing_percentage,
        "result": quiz_attempt.result,
        "quiz_status": quiz_attempt.quiz_status,
        "started_at": quiz_attempt.started_at,
        "ended_at": quiz_attempt.ended_at
    }

    return Response(result_data, status=status.HTTP_200_OK)









#Time_Spent

from datetime import timedelta
from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import ReviewSession
from .authentication import CustomJWTAuthentication  # Assuming you're using JWT authentication
from datetime import datetime, timedelta
from django.utils import timezone


# 🟢 Helper function to convert hours (float) to "xh ym" format
def format_time_spent(time_spent):
    hours, minutes = divmod(int(time_spent * 60), 60)  # Convert to minutes and split
    return f"{hours}h {minutes}m"

# 🟢 Helper function to generate a list of all dates in a given period (e.g., week, month)
def generate_date_range(start_date, end_date):
    date_list = []
    current_date = start_date
    while current_date <= end_date:
        date_list.append(current_date)
        current_date += timedelta(days=1)
    return date_list

# 🟢 Day summary API (Shows today's date even if 0 hours spent)
@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def day_summary(request):
    user = request.user
    today = timezone.now().date()
    start_of_day = timezone.make_aware(datetime.combine(today, datetime.min.time()))
    end_of_day = start_of_day + timedelta(days=1)

    # Get all review sessions for today
    sessions = ReviewSession.objects.filter(user=user, reviewed_at__gte=start_of_day, reviewed_at__lt=end_of_day)

    # Calculate total hours spent today
    total_hours = sum(session.time_spent for session in sessions)

    return Response({
        'date': today.strftime('%Y-%m-%d'),
        'total_hours_spent': format_time_spent(total_hours)  # 🟢 Format hours & minutes
    })

# 🟢 Week summary API (Shows all 7 days even if 0 hours spent)
@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def week_summary(request):
    user = request.user
    today = timezone.now().date()
    start_of_week = today - timedelta(days=today.weekday())
    end_of_week = start_of_week + timedelta(days=6)

    # Convert to timezone-aware datetimes
    start_of_week = timezone.make_aware(datetime.combine(start_of_week, datetime.min.time()))
    end_of_week = timezone.make_aware(datetime.combine(end_of_week, datetime.max.time()))

    # Get all review sessions within the week
    sessions = ReviewSession.objects.filter(user=user, reviewed_at__gte=start_of_week, reviewed_at__lte=end_of_week)

    # Aggregate sessions by day
    daily_reviews = {date.strftime('%Y-%m-%d'): 0 for date in generate_date_range(start_of_week.date(), end_of_week.date())}

    for session in sessions:
        session_date = session.reviewed_at.date().strftime('%Y-%m-%d')
        daily_reviews[session_date] += session.time_spent

    return Response({
        'week_start': start_of_week.strftime('%Y-%m-%d'),
        'week_end': end_of_week.strftime('%Y-%m-%d'),
        'daily_hours_spent': [{'date': date, 'hours_spent': format_time_spent(hours)} for date, hours in daily_reviews.items()]
    })

# 🟢 Month summary API (Shows all days even if 0 hours spent)
@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def month_summary(request):
    user = request.user
    today = timezone.now().date()
    start_of_month = today.replace(day=1)
    next_month = (start_of_month + timedelta(days=32)).replace(day=1)  # First day of next month
    end_of_month = next_month - timedelta(days=1)  # Last day of this month

    # Convert to timezone-aware datetimes
    start_of_month = timezone.make_aware(datetime.combine(start_of_month, datetime.min.time()))
    end_of_month = timezone.make_aware(datetime.combine(end_of_month, datetime.max.time()))

    # Get all review sessions within the month
    sessions = ReviewSession.objects.filter(user=user, reviewed_at__gte=start_of_month, reviewed_at__lte=end_of_month)

    # Aggregate sessions by day
    daily_reviews = {date.strftime('%Y-%m-%d'): 0 for date in generate_date_range(start_of_month.date(), end_of_month.date())}

    for session in sessions:
        session_date = session.reviewed_at.date().strftime('%Y-%m-%d')
        daily_reviews[session_date] += session.time_spent

    return Response({
        'month_start': start_of_month.strftime('%Y-%m-%d'),
        'month_end': end_of_month.strftime('%Y-%m-%d'),
        'daily_hours_spent': [{'date': date, 'hours_spent': format_time_spent(hours)} for date, hours in daily_reviews.items()]
    })

# 🟢 Year summary API (Shows all 12 months even if 0 hours spent)
@api_view(['GET'])
@authentication_classes([CustomJWTAuthentication])
@permission_classes([IsAuthenticated])
def year_summary(request):
    user = request.user
    today = timezone.now().date()

    # Get year from query parameters (e.g., /api/year-summary/?year=2024)
    year = request.GET.get('year', today.year)
    try:
        year = int(year)
    except ValueError:
        return Response({'error': 'Invalid year format. Please provide a valid year.'}, status=400)

    start_of_year = timezone.make_aware(datetime(year, 1, 1))
    end_of_year = timezone.make_aware(datetime(year + 1, 1, 1))

    # Get all review sessions within the year
    sessions = ReviewSession.objects.filter(user=user, reviewed_at__gte=start_of_year, reviewed_at__lt=end_of_year)

    # Aggregate sessions by month
    monthly_reviews = {f"{year}-{month:02d}": 0 for month in range(1, 13)}

    for session in sessions:
        session_month = session.reviewed_at.strftime('%Y-%m')
        monthly_reviews[session_month] += session.time_spent

    return Response({
        'selected_year': year,
        'year_start': start_of_year.strftime('%Y-%m-%d'),
        'year_end': end_of_year.strftime('%Y-%m-%d'),
        'monthly_hours_spent': [{'month': month, 'hours_spent': format_time_spent(hours)} for month, hours in monthly_reviews.items()]
    })

from rest_framework.exceptions import ValidationError

class ResendOTPView(GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'message': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            send_code_to_user(email)  # This will raise an error if the user must wait
            return Response({'message': 'A new OTP has been sent to your email, valid for 1 minute.'}, status=status.HTTP_200_OK)
        except ValueError as e:
            return Response({'message': str(e)}, status=status.HTTP_429_TOO_MANY_REQUESTS)  # 429 Too Many Requests
        except User.DoesNotExist:
            return Response({'message': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)



























