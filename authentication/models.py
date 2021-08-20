
from django.db import models
from django.contrib.auth.models import User

class UserOTP(models.Model):
	user = models.CharField(max_length=39)
	time_st = models.DateTimeField(auto_now = True)
	otp = models.SmallIntegerField()

class EmailOTP(models.Model):
	
	time_st = models.DateTimeField(auto_now = True)
	otp = models.SmallIntegerField()


