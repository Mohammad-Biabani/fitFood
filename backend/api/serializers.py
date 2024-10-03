from rest_framework import serializers
from .models import *

  
class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = ['id', 'C_userName', 'password', 'C_name', 'C_address', 'C_phoneNumber', 'C_credit']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
    
class CustomerUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = ['id', 'C_userName', 'C_name', 'C_address', 'C_phoneNumber']
            

class CreditSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = ['id', 'C_userName', 'password', 'C_name', 'C_address', 'C_phoneNumber', 'C_credit']



class Catering_adminSerializer(serializers.ModelSerializer):
    class Meta:
        model = Catering_admin
        fields = '__all__'
        extra_kwargs = {
            'password': {'write_only': True}
        }


class Delivery_adminSerializer(serializers.ModelSerializer):
    class Meta:
        model = Delivery_admin
        fields = '__all__'
        extra_kwargs = {
            'password': {'write_only': True}
        }
    
    
class FoodSerializer(serializers.ModelSerializer):
	class Meta:
		model = Food
		fields ='__all__'
  

class PackSerializer(serializers.ModelSerializer):
	class Meta:
		model = Pack
		fields ='__all__'


class OrderSerializer(serializers.ModelSerializer):
	class Meta:
		model = Order
		fields =['id', 'customerID', 'foodID', 'quantity', 'orderDate']