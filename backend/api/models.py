from django.db import models
from django.contrib.auth.models import AbstractUser
    
    
class Customer(AbstractUser):
    C_userName = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    C_name = models.CharField(max_length=255)
    C_address = models.CharField(max_length=255)
    C_phoneNumber = models.CharField(max_length=255)
    C_credit = models.FloatField(default=0)
    username = None

    USERNAME_FIELD = 'C_userName'
    REQUIRED_FIELDS = []
    
    
class Catering_admin(models.Model):
    CA_username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)

    
class Delivery_admin(models.Model):
    DA_username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)

    
class Food(models.Model):    
    foodName = models.CharField(max_length=255)
    price = models.FloatField()
    category = models.CharField(max_length=255)
    description = models.CharField(max_length=500, default='')
    CAdminID = models.ForeignKey(Catering_admin, on_delete=models.CASCADE, null=True)
    

class Pack(models.Model):    
    customerID = models.ForeignKey(Customer, on_delete=models.CASCADE)
    orderDate = models.CharField(max_length=255)
    totalCost = models.FloatField(default=0)
    PStatus = models.BooleanField(default=False)
    DAdminID = models.ForeignKey(Delivery_admin, on_delete=models.CASCADE, null=True)
    

class Order(models.Model):    
    customerID = models.ForeignKey(Customer, on_delete=models.CASCADE)
    foodID = models.ForeignKey(Food, on_delete=models.CASCADE)
    quantity = models.IntegerField()
    orderDate = models.CharField(max_length=255)
    OStatus = models.BooleanField(default=False)
    O_Status_Check = models.BooleanField(default=False)
    packID = models.ForeignKey(Pack, on_delete=models.CASCADE, null=True)
    CAdminID = models.ForeignKey(Catering_admin, on_delete=models.CASCADE, null=True)

