
from authentication.serializers import ChangePasswordSerializer
from django.urls import path
from . import views
from rest_framework_simplejwt import views as jwt_views


#creating router object


urlpatterns = [
   
    path('register/',views.RegisterView.as_view()),
    path('login/',views.LoginView.as_view(),name='login'),
    path('registerverify/',views.registerverify.as_view()),
    #path('registerverify/',views.registerverify),
    path('changepassword/', views.ChangePasswordView.as_view()),

    path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/oauth/login/', views.AuthGoogle.as_view(), name='AuthGoogle'),
    
  
]

