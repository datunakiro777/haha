from rest_framework.routers import DefaultRouter
from users.views import UserViewSet,UserRegisterViewSet, ResetPasswordView, ResetPasswordViewConfirm
from django.urls import path, include
router = DefaultRouter()
router.register('users', UserViewSet, basename='users')
router.register('register', UserRegisterViewSet, basename='register')
router.register('reset_password', ResetPasswordView, basename='reset_password')


urlpatterns = [
    path('', include(router.urls)),
    path('password/reset_confirm/<uidb64>/<token>/', ResetPasswordViewConfirm.as_view({"post" : "create"}), name='reset_password_confirm')
]
