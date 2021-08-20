from rest_framework import serializers
from django.contrib.auth.models import User


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=65, min_length=8, write_only=True)
    email = serializers.EmailField(max_length=255, min_length=4),
    first_name = serializers.CharField(max_length=255, min_length=2)
    last_name = serializers.CharField(max_length=255, min_length=2)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password'
                  ]

    #def validate(self, attrs):
    #    email = attrs.get('email', '')
    #    if User.objects.filter(email=email).exists():
    #        raise serializers.ValidationError(
    #            {'email': ('Email is already in use')})
    #    return super().validate(attrs)

    def create(self, validated_data):
        usr = User.objects.create_user(**validated_data)
        usr.is_active = False
        usr.save()
        return usr


class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=65, min_length=8, write_only=True)
    username = serializers.CharField(max_length=255, min_length=2)

    class Meta:
        model = User
        fields = ['username', 'password']

class EmailTokenSerializer(serializers.Serializer):
    otp=serializers.CharField(max_length=10)

class PasswordresetSerializer(serializers.Serializer):
    email=serializers.CharField(max_length=10)



class ChangePasswordSerializer(serializers.Serializer):
    model = User
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class SocialSerializer(serializers.Serializer):
      provider = serializers.CharField(max_length=255, required=True)
      access_token = serializers.CharField(max_length=4096, required=True, trim_whitespace=True)