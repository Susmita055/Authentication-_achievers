from django.shortcuts import render, redirect

from rest_framework.generics import GenericAPIView
from .serializers import UserSerializer, LoginSerializer,EmailTokenSerializer,PasswordresetSerializer
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.contrib import auth
from .models import UserOTP
import random
from django.core.mail import send_mail
import jwt
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponse, Http404, JsonResponse
# for password reset
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
# Create your views here.


class RegisterView(GenericAPIView):
    serializer_class = UserSerializer

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        data = request.data
        if serializer.is_valid():
            serializer.save()
            usr_otp = random.randint(100000, 999999)
            usr=data.get('username', '')
            email=data.get('email','')	
            mess = f"Hello suman,\nYour OTP is {usr_otp}\nThanks!\nhttp://127.0.0.1:8000/admin/"
            UserOTP.objects.create(user = usr, otp = usr_otp)
            send_mail(
				"Welcome to ITScorer - Verify Your Email",
				mess,
				settings.EMAIL_HOST_USER,
				[email],
				fail_silently = False
				)

            
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from datetime import datetime, timedelta
from django.utils import timezone
now = timezone.now()
class registerverify(GenericAPIView):
    serializer_class = EmailTokenSerializer
    def post(self, request):
       data = request.data
       get_otp = data.get('otp')
       print(get_otp)
       print(get_otp)
       try:
           if get_otp:
            get = UserOTP.objects.get(otp=get_otp)
            get_usr=get.user
            db_time=get.time_st+timedelta(hours=0.4)
            print(type(db_time))
            print(type(timezone.now()))
            usr = User.objects.get(username=get_usr)
           if int(get_otp) == UserOTP.objects.filter(user = usr).last().otp  and not(timezone.now()>db_time):
               usr.is_active = True
               usr.save()
               messages.success(request, f'Account is Created ')
               return redirect('login')
       except UserOTP.DoesNotExist:
                messages.warning(request,f'you entered a wrong otp')
                #return render(request,'resendopt.html',{'otp': True, 'usr':usr})

       return HttpResponse("invalid token")
    

class password_reset_request(GenericAPIView):
    serializer_class = PasswordresetSerializer
    def post(self, request):
        data = request.data
        email=data.get('email')
        user= User.objects.get(email=email)
        if user:
            subject='password RESET Request'
            email_template_name='password_reset_email.txt'
            c={
                'email': user.email,
                'domain': '127.0.0.1:8000',
                'site': 'demo website',
                "user": user,
                'token':default_token_generator.make_token(user),
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                'protocol': 'http',
            }
            email= render_to_string(email_template_name,c)
            send_mail(subject,email,'abc@gmailcom',[user.email],fail_silently=False)
        messages.error(request, 'An invalid email has been entered.')




   



class LoginView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        data = request.data
        username = data.get('username', '')
        password = data.get('password', '')
        user = auth.authenticate(username=username, password=password)

        if user:
            auth_token = jwt.encode(
                {'username': user.username}, settings.JWT_SECRET_KEY, algorithm="HS256")

            serializer = UserSerializer(user)

            data = {'user': serializer.data, 'token': auth_token}

            return Response(data, status=status.HTTP_200_OK)

            # SEND RES
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)




    
            

from rest_framework import generics
from .serializers import ChangePasswordSerializer,SocialSerializer

from rest_framework.permissions import IsAuthenticated   
class ChangePasswordView(generics.UpdateAPIView):
        
        serializer_class = ChangePasswordSerializer
        model = User
        permission_classes = (IsAuthenticated,)

        def get_object(self, queryset=None):
            obj = self.request.user
            return obj

        def update(self, request, *args, **kwargs):
            self.object = self.get_object()
            serializer = self.get_serializer(data=request.data)

            if serializer.is_valid():
                # Check old password
                if not self.object.check_password(serializer.data.get("old_password")):
                    return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
                # set_password also hashes the password that the user will get
                self.object.set_password(serializer.data.get("new_password"))
                self.object.save()
                response = {
                    'status': 'success',
                    'code': status.HTTP_200_OK,
                    'message': 'Password updated successfully',
                    'data': []
                }

                return Response(response)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)







import uuid
from django.conf import settings
import json
from rest_framework_jwt.settings import api_settings
from rest_framework.views import APIView
JWT_PAYLOAD = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE = api_settings.JWT_ENCODE_HANDLER

class AuthGoogle(APIView):
    serializer_class = SocialSerializer
    def post(self, request):

        data = dict(client_id=request.data.get('clientId'),
                    redirect_uri=request.data.get('redirectUri'),
                    client_secret=settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
                    code=request.data.get('code'),
                    grant_type='authorization_code')
        print(data)
        print(settings.ACCESS_TOKEN_URL)
        # Obteniendo Access Token
        r = requests.post(settings.ACCESS_TOKEN_URL, data=data)
        token = json.loads(r.text)
        print(token)
        headers = {'Authorization': 'Bearer {0}'.format(token['access_token'])}

        # Obteniendo datos de perfil

        r = requests.get(settings.PEOPLE_API_URL, headers=headers)

        profile = json.loads(r.text)

        print(profile['email'])

        try:
            user = User.objects.get(email=profile['email'])
        except User.DoesNotExist:
            user = None

        if user:
            payload = JWT_PAYLOAD(user)
            token = JWT_ENCODE(payload)
            return Response({'token': token}, status.HTTP_200_OK)

        else:
            payload = JWT_PAYLOAD(user)
            token = JWT_ENCODE(payload)
            return Response({'token': token}, status.HTTP_201_CREATED)