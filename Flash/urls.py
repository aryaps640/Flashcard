from django.urls import path, include
from rest_framework.routers import DefaultRouter
from Flash import views
from rest_framework.routers import DefaultRouter
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from .views import (AllReviewFlashcardsView,MCQuestionViewSet,  MCQAnswerViewSet, QuestionsViewSet,AnswersViewSet, 
FillQuestionViewSet, FillAnswerViewSet,CheckStatementViewSet, QuizViewSet, ReviewFlashcardsBySubfolderView, ReviewFlashcardsView,TrueFalseViewSet,FeedbackViewSet,mcq_crud,fib_crud,sub_crud,truefalse_crud,manage_tags, 
QuestionFeedbackView,RegisterUserView, VerifyUserEmail,  TestingAuthenticatedReq,VerifyUserEmail, TestingAuthenticatedReq, PasswordResetConfirm, PasswordResetRequestView,
SetNewPasswordView, LogoutApiView, weekly_summary, daily_summary, monthly_summary, get_user_sessions, LoginUserView, ResendOTPView)
from .views import GoogleLoginAPIView
from .views import get_quiz_attempt_result

router = DefaultRouter()
router.register(r'mcq-quesans', views.MCQuestionViewSet, basename='MCQ Flashcard')
router.register(r'mcqanswers', views.MCQAnswerViewSet)
router.register(r'sub-quesans', views.QuestionsViewSet, basename='SUB Flashcard')
router.register(r'sub-answer', views.AnswersViewSet, basename=' Sub Answer')
router.register(r'fillups-quesans', views.FillQuestionViewSet, basename='FILL UPS Flashcard')
router.register(r'fillanswers', views.FillAnswerViewSet)
router.register(r'truefalse-quesans', views.CheckStatementViewSet, basename= 'Check Statement')
router.register(r'folders', views.FolderViewSet, basename='Folder')
router.register(r'files', views.FileViewSet, basename= 'Files')
router.register(r'truefalse-answers', views.TrueFalseViewSet, basename= 'True False')
router.register(r'directory', views.DirectoryViewSet, basename='directory')
router.register(r'feedbacks', FeedbackViewSet, basename='feedback')
#router.register(r'quizzes', views.QuizViewSet)
router.register(r'quiz', QuizViewSet, basename='quiz')


urlpatterns = [
    path('', include(router.urls)),
    path('subfolder/<int:pk>/create_subfolder/', views.FolderViewSet.as_view({'post': 'create_subfolder_by_subfolder_id'})),    #Done
    path('folders/<int:pk>/create_subfolder/', views.FolderViewSet.as_view({'post': 'create_subfolder_by_subfolder_id'}), name='create-subfolder'),  #Done
    path('mcq_questions/', views.mcq_questions, name='mcq_questions'),  #Done
    path('subfolder/<int:subfolder_id>/', views.get_questions_by_subfolder, name='get-questions-by-subfolder'),  #Done
    path('mcq_answers/', views.mcq_answers, name='mcq_answers'), #done
    path('FillupQuestions/', views.FillupQuestions, name='FillupQuestions'),  #done
    path('FillupAnswers/', views.FillupAnswers, name='FillupAnswers'), #done
    path('home/', views.home, name='home'),  #Done
    path('all_mcq_questions_and_answers/', views.all_mcq_questions_and_answers, name='all_mcq_questions_and_answers'),  #done
    path('all_fill_questions_and_answers/', views.all_fill_questions_and_answers, name='all_fill_questions_and_answers'), #done
    path('cards/', views.cards, name='cards'),  #Done
    path('flashcard/', views.flashcard, name='flashcard'),  # Done
    path('questions/combined/<int:folder_id>/', views.CombinedQuestionsByFolderAPIView.as_view(), name='combined-questions-by-folder'),
    path('feedback_detail/<int:feedback_id>/', views.feedback_detail, name='feedback_detail'),
    path('subfolder/<int:subfolder_id>/mcq/', mcq_crud),  #Done
    path('subfolder/<int:subfolder_id>/mcq/<str:question_id>/', mcq_crud,name='MCQ by subfolder'),  #Done
    path('subfolder/<int:subfolder_id>/fib/', fib_crud),  #Done
    path('subfolder/<int:subfolder_id>/fib/<int:question_id>/', fib_crud,name='Fill Ups by subfolder'),  #Done
    path('subfolder/<int:subfolder_id>/sub/', sub_crud),  #Done
    path('subfolder/<int:subfolder_id>/sub/<int:question_id>/', sub_crud,name='Subjective by subfolder'),  #Done
    path('subfolder/<int:subfolder_id>/truefalse/', truefalse_crud),  #Done
    path('subfolder/<int:subfolder_id>/truefalse/<int:question_id>/', truefalse_crud,name='Truefalse by subfolder'),  #Done
    path('subfolder/<int:subfolder_id>/tags/<str:question_type>/<int:question_id>/', manage_tags, name='manage_tags'), #done
    path('subfolder/<int:subfolder_id>/tags/<str:question_type>/<int:question_id>/<int:tag_id>/', manage_tags, name='manage_tags_with_tag_id'), #Done
    path('subfolder/<int:subfolder_id>/feedbacks/<str:question_type>/', QuestionFeedbackView.as_view(), name='question_feedback_list'),
    path('subfolder/<int:subfolder_id>/feedbacks/<str:question_type>/<str:question_id>/', QuestionFeedbackView.as_view(), name='question_feedback_detail'),
    path('subfolder/<int:subfolder_id>/feedbacks/<str:question_type>/<int:question_id>/', QuestionFeedbackView.as_view(), name='feedback_detail_update_delete'),
    path('subfolder/<int:subfolder_id>/uploaded_images/', views.manage_uploaded_images, name='manage_uploaded_images'),  #done
    path('subfolder/<int:subfolder_id>/uploaded_images/<int:question_id>/', views.manage_uploaded_images, name='manage_uploaded_image_detail'),  #done
    path('subfolders/<int:pk>/move_subfolder/', views.FolderViewSet.as_view({'post': 'move_subfolder'}), name='move-subfolder'),  #done
    path('review-schedule/', ReviewFlashcardsView.as_view(), name='review-schedule'),
    path('review-schedule/subfolder/<int:subfolder_id>/', ReviewFlashcardsBySubfolderView.as_view(), name='review-flashcards-by-subfolder'),
    path('flashcard-review/', AllReviewFlashcardsView.as_view(), name='flashcard-review/'),
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify/', VerifyUserEmail.as_view(), name='verify'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('test/', TestingAuthenticatedReq.as_view(), name='test'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/<str:uidb64>/<str:token>/', PasswordResetConfirm.as_view(), name='reset-password-confirm'),
    path('set-new-password/<uidb64>/<token>/', SetNewPasswordView.as_view(), name='set-new-password'),
    path('logout/', views.logout_user, name='logout'),
    path('weekly-summary/', weekly_summary, name='weekly-summary'),
    path('daily-summary/', daily_summary, name='daily_summary'),
    path('monthly-summary/', monthly_summary, name='monthly_summary'),
    path('yearly-summary/', views.yearly_summary, name='yearly-summary'),
    path('api/sessions/', get_user_sessions, name='user-sessions'),
    path('auth/sessions/', views.get_user_sessions, name='get_user_sessions'),
    path('auth/sessions/clear/', views.clear_sessions, name='clear_sessions'),
    path('auth/sessions/cleanup/', views.cleanup_user_sessions, name='cleanup_sessions'),
    path('clear-sessions/', views.clear_sessions, name='clear-sessions'),

    path('quiz/<int:quiz_id>/questions/', views.get_quiz_questions, name='get-quiz-questions'),

    path('quiz/<int:quiz_id>/submit/', views.submit_quiz_answers, name='submit-quiz-answers'),
    path('quiz/<int:quiz_id>/result/', views.get_quiz_result, name='quiz-result'),
    path('quiz/<int:quiz_id>/attempt/<int:attempt_number>/', get_quiz_attempt_result, name='get_quiz_attempt_result'),
    path('api/day-summary/', views.day_summary, name='day_summary'),
    path('api/week-summary/', views.week_summary, name='week_summary'),
    path('api/month-summary/', views.month_summary, name='month_summary'),
    path('api/year-summary/', views.year_summary, name='year_summary'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),

    path('auth/google/', GoogleLoginAPIView.as_view(), name='google_login'),



] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)