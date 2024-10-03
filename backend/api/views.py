from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .serializers import *
from .models import *
import jwt, datetime




class Greeting(APIView):
    """_summary_

    Returns a JSON response with a welcome message.
    
    
    GET localhost:8000/api/
    
    Request Body:
        None
    """

    def get(self, request): 
        data = {
            'message': 'Hi there, welcom to FitFood.'
            }
        return Response(data)
    
class see_all_foods(APIView):
    """_summary_
    
    Retrieves a list of all food items and returns them in a serialized format.
    
    
    GET localhost:8000/api/foods/

    Request Body:
        None
    """
    
    def get(self, request):
        foods = Food.objects.all().order_by('id')
        serializer = FoodSerializer(foods, many=True)
        return Response(serializer.data)

###############################################################################


class sign_up_a_customer(APIView):
    """_summary_
    
    Handles POST requests for customer signup.

    This endpoint allows users to register as new customers by providing their details
    in the request body. It expects a valid serialized Customer object in the request data.

    The `CustomerSerializer` is used to validate and save the customer
    data. If the data is valid, a new customer object is created and a successful response
    is returned containing the serialized data of the newly created customer.

    Raises a validation error if the provided customer data is invalid.


    POST localhost:8000/api/customer/signUp/

    Request Body:
        {
            "C_userName": "customerUsername",
            "password": "customerPassword", 
            "C_name": "customerName", 
            "C_address": "customerAddress" , 
            "C_phoneNumber": "098915" 
        }
    """
    
    def post(self, request):
        serializer = CustomerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
 
    
class customer_login(APIView):
    """_summary_
    
    Handles POST requests for customer login.

    This endpoint allows customers to authenticate by providing their username and password
    in the request body. It retrieves the matching customer object from the database
    and validates the credentials.

    On successful login:
        - A JWT token is generated containing the customer ID and expiration time.
        - The token is stored in a cookie named `jwt` with the `httponly` flag set.
        - A JSON response is returned containing the generated token.

    Raises exceptions (AuthenticationFailed) for invalid username or password.


    POST localhost:8000/api/customer/login/
    
    Request Body:
        {
            "username" : "customerUsername",
            "password" : "customerPassword"
        }
    """
    
    def post(self, request):
        C_userName = request.data['username']
        password = request.data['password']

        user = Customer.objects.filter(C_userName=C_userName).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.now(datetime.timezone.utc)
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256') #.decode('utf-8')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }
        return response
 
   
class see_a_customer_info(APIView):
    """_summary_
    
    Handles GET requests to retrieve a customer's information.

    This endpoint allows authorized customers to access their own information. It expects a valid
    JWT token to be included in the request cookies.

    - The request's `jwt` cookie is retrieved.
    - If no token is found, an `AuthenticationFailed` exception is raised.
    - The token is decoded using the secret key and the HS256 algorithm.
    - If the token decoding fails, an `AuthenticationFailed` exception is raised.
    - The customer ID is extracted from the payload of the decoded JWT token.
    - The customer object is retrieved from the database based on the ID.
    - A `CustomerSerializer` is used to serialize the retrieved customer object.
    - A successful response is returned containing the serialized customer data.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/customer/info/

    Request Body:
        None
    """

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except: 
            raise AuthenticationFailed('Unauthenticated!')

        user = Customer.objects.filter(id=payload['id']).first()
        serializer = CustomerSerializer(user)
        return Response(serializer.data)


class edit_a_customer_info(APIView):
    """_summary_
    
    Handles POST requests to edit a customer's information.

    This endpoint allows authenticated customers to update their own information by providing
    the updated data in the request body. It expects a valid JWT token in the request cookies
    for authentication.

    - The request's `jwt` cookie is retrieved.
    - If no token is found, an `AuthenticationFailed` exception is raised.
    - The token is decoded using the secret key and the HS256 algorithm.
    - If the token decoding fails, an `AuthenticationFailed` exception is raised.
    - The customer ID is extracted from the payload of the decoded JWT token.
    - The customer object is retrieved from the database based on the ID.
    - A copy of the request data is created to avoid modifying the original data.
    - A `CustomerUpdateSerializer` is used to validate and update the customer object with
        the provided data.
    - If the data is valid, the changes are saved to the database.
    - A successful response is returned containing the serialized data of the updated customer.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    POST localhost:8000/api/customer/update/

    Request Body:
        {
            "C_userName": "newCustomreUsername",
            "C_name": "newCustomerName", 
            "C_address": "newCustomreAddress" , 
            "C_phoneNumber": "098910" 
        }
    """
    
    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        user = Customer.objects.filter(id=payload['id']).first()
        data = request.data.copy()
        serializer = CustomerUpdateSerializer(instance=user, data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    

class charge_a_customer_credit(APIView):
    """_summary_
    
    Handles POST requests to charge a customer's credit.

    This endpoint allows authenticated customers to top up their credit by providing the charge amount
    in the request body. It expects a valid JWT token in the request cookies for authentication.

    - The request's `jwt` cookie is retrieved for authentication.
    - If no token is found, an `AuthenticationFailed` exception is raised.
    - The token is decoded to extract the customer ID.
    - If the token decoding fails, an `AuthenticationFailed` exception is raised.
    - The customer object is retrieved from the database based on the ID.
    - A copy of the customer object is created (`updated_user`) to avoid modifying the original
        object directly.
    - The charge amount is extracted from the request data and converted to a float.
    - The customer's credit in `updated_user` is increased by the charge amount.
    - A temporary `CreditSerializer` is used to serialize the updated credit information
        (potentially for validation or logging).
    - A `CustomerSerializer` is used to validate and save the updated customer object 
        (including the increased credit).
    - If the data is valid, the changes are saved to the database.
    - A successful response is returned containing the serialized data of the updated customer.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.


    POST localhost:8000/api/customer/charge/

    Request Body:
        {
            "charge": "120"
        }
    """
    
    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        user = Customer.objects.filter(id=payload['id']).first()
        updated_user = user
        updated_user.C_credit += float(request.data['charge'])
        temp_serializer = CreditSerializer(updated_user)
        
        serializer = CustomerSerializer(instance=user, data=temp_serializer.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
        

class add_an_order(APIView):
    """_summary_
    
    Handles POST requests to create a new order for a customer.

    This endpoint allows authenticated customers to place orders for food items. It expects a valid
    JWT token in the request cookies for authentication and requires the following data in the request body:

    - foodID: The ID of the food item to be ordered (integer)
    - quantity: The desired quantity of the food item (integer)

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the food item based on the provided ID.
    - Validates if the food item exists.
    - Calculates the total cost based on the food item price and requested quantity.
    - Checks if the customer has sufficient credit to cover the order cost.
    - If insufficient credit, returns an error response.
    - Decreases the customer's credit by the order total.
    - Updates the customer's credit (potentially for validation or logging using a temporary serializer).
    - Validates and saves the updated customer information.
    - Creates a new order object with the provided data, including the customer ID and food details.
    - Validates and saves the new order object.
    - Returns a successful response containing the serialized data of the created order.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.


    POST localhost:8000/api/customer/order/

    Request Body:
        {
            "foodID": "1",
            "quantity": "2",
            "orderDate": "1403-07-21"
        }
    """
    
    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        user = Customer.objects.filter(id=payload['id']).first()
        updated_user = user
        food = Food.objects.filter(id=request.data['foodID']).first()

        if not food:
            return Response('There is no food with such ID.')

        decrease_credit_amount = food.price * int(request.data['quantity']) 

        if updated_user.C_credit < decrease_credit_amount:
            return Response('You do not have enough credit')

        updated_user.C_credit -= decrease_credit_amount
        
        temp_serializer = CreditSerializer(updated_user)
        
        serializer = CustomerSerializer(instance=user, data=temp_serializer.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        data = request.data.copy()
        data['customerID'] = payload['id']
        
        serializer = OrderSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
              

class edit_a_customer_order(APIView):
    """_summary_
    
    Handles POST requests to edit a customer's order.

    This endpoint allows authenticated customers to modify their existing orders. It expects a valid JWT token
    in the request cookies for authentication and requires the following data in the request body:

    - orderID: The ID of the order to be edited (integer)
    - foodID (optional): The ID of the new food item (if updating the food)
    - quantity (optional): The desired quantity of the food item (if updating the quantity)

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the order object based on the provided ID.
    - Verifies if the retrieved order belongs to the authenticated customer.
    - Creates a copy of the request data for modification.
    - Sets the `customerID` in the copied data to the authenticated user's ID.
    - Retrieves the customer object and both the current and updated food items (if provided).
    - Calculates the credit difference based on the old and new food quantities and prices.
    - Checks if the customer has sufficient credit to cover the effective price change.
    - If insufficient credit, returns an error response.
    - Updates the customer's credit balance based on the credit difference.
    - Validates and saves the updated customer information.
    - Updates the order object with the modified data from the request body.
    - Validates and saves the updated order object.
    - Returns a successful response containing the serialized data of the edited order.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.


    POST localhost:8000/api/customer/orderUpdate/

    Request Body:
        {
            "orderID": "1",
            "foodID": "2",
            "quantity": "1",
            "orderDate": "1403-07-22"
        }
    """
    
    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        order = Order.objects.filter(id=request.data['orderID']).first()
        
        if order.customerID.id != int(payload['id']):
            return Response('Bad request.')

        updated_order = request.data.copy()
        updated_order['customerID'] = payload['id']
        
        customer = Customer.objects.filter(id=updated_order['customerID']).first()
        old_food = Food.objects.filter(id=order.foodID.id).first()
        updated_food = Food.objects.filter(id=updated_order['foodID']).first()
        
        old_decrease_credit_amount = int(order.quantity) * old_food.price
        updated_decrease_credit_amount = int(updated_order['quantity']) * updated_food.price

        if (customer.C_credit + old_decrease_credit_amount) >= updated_decrease_credit_amount:
            customer.C_credit = customer.C_credit + old_decrease_credit_amount - updated_decrease_credit_amount
            customer.save()
        else:
            return Response('You do not have enough credit.')

        serializer = OrderSerializer(instance=order, data=updated_order)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)        


class see_a_customer_all_orders(APIView):
    """_summary_
    
    Handles GET requests to retrieve all orders for an authenticated customer.

    This endpoint allows authenticated customers to view their complete order history. It expects a valid JWT token
    in the request cookies for authentication.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves all order objects belonging to the authenticated customer based on the customer ID
        extracted from the decoded JWT token.
    - If no orders are found, returns a response with an informative message.
    - Serializes the retrieved orders using the `OrderSerializer` for converting them to a JSON format.
    - Returns a successful response containing the serialized data of all the customer's orders.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/customer/ordersInfo/

    Request Body:
        None
    """
    
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')

        orders = Order.objects.filter(customerID=payload['id']).all()
        
        if not orders:
            response = Response()
            response.data = {'message': 'There is no order.'}
            return response
            
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)


class customer_logout(APIView):
    """_summary_
    
    Handles POST requests to log out a customer.

    This endpoint allows authenticated customers to log out of the application. It deletes the JWT token
    stored in the 'jwt' cookie upon successful logout.

    - Deletes the 'jwt' cookie from the response to clear the authentication token.
    - Returns a success message in the response body.


    POST localhost:8000/api/customer/logout/

    Request Body:
        None
    """
    
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response
    
    
################################################################################


class delivery_admin_login(APIView):
    """_summary_
    
    Handles POST requests to authenticate a delivery administrator.

    This endpoint allows delivery administrators to log in to the application using their username and password.
    Upon successful login, it generates a JWT token and sets it as a cookie
    named 'jwt' in the response.

    - Retrieves username and password from the request body.
    - Attempts to find a DeliveryAdmin object matching the provided username.
    - Raises an `AuthenticationFailed` exception if the username is not found.
    - Verifies the password for the retrieved DeliveryAdmin object.
    - Raises an `AuthenticationFailed` exception if the password is incorrect.
    - Creates a payload with user ID, expiration time, and issued-at time.
    - Encodes the payload into a JWT token using the 'delivery_admin_secret_code' and HS256 algorithm.
    - Sets the JWT token as a cookie named 'jwt' with the HttpOnly flag enabled for security.
    - Returns a response containing the generated JWT token in the body.

    Raises `AuthenticationFailed` exceptions for invalid username or password.


    POST localhost:8000/api/deliveryAdmin/login/

    Request Body:
        {
            "username" : "deliveryAdminUsername",
            "password" : "deliveryAdminPassword"
        }
    """
    
    def post(self, request):
        DA_username = request.data['username']
        password = request.data['password']

        user = Delivery_admin.objects.filter(DA_username=DA_username).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if user.password != password:
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.now(datetime.timezone.utc)
        }

        token = jwt.encode(payload, 'delivery_admin_secret_code', algorithm='HS256') #.decode('utf-8')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }
        return response
    
    
class see_All_packs(APIView):
    """_summary_
    
    Handles GET requests to retrieve all packs for a delivery administrator.

    This endpoint allows authorized delivery administrators to view all existing packs in the system. 
    It requires a valid JWT token in the request cookies for authentication.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves all Pack objects from the database.
    - If no packs are found, returns a response with an informative message.
    - Serializes the retrieved packs using the `PackSerializer` for converting them to a JSON format.
    - Returns a successful response containing the serialized data of all packs.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/deliveryAdmin/packs/

    Request Body:
        None
    """
    
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'delivery_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')

        packs = Pack.objects.all()
        
        if not packs:
            response = Response()
            response.data = {'message': 'There is no pack.'}
            return response
            
        serializer = PackSerializer(packs, many=True)
        return Response(serializer.data)
    

class see_a_spec_pack(APIView):
    """_summary_
    
    Handles GET requests to retrieve a specific pack by ID for a delivery administrator.

    This endpoint allows authorized delivery administrators to view details of a particular pack
    based on its ID. It requires a valid JWT token in the request cookies for authentication.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the Pack object with the ID provided in the request body.
    - Returns an error message if the pack with the specified ID is not found.
    - Serializes the retrieved pack using the `PackSerializer` for converting it to a JSON format.
    - Returns a successful response containing the serialized data of the specific pack.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/deliveryAdmin/pack/

    Request Body:
        {
            "packID" : "1"
        }
    """

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'delivery_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')

        pack = Pack.objects.filter(id=request.data['packID']).first()
        if not pack:
            return Response('There is no pack with such ID')
        serializer = PackSerializer(pack)
        return Response(serializer.data)
    

class turn_a_pack_status_to_sent(APIView):
    """_summary_
    
    Handles POST requests to mark a pack as sent by a delivery administrator.

    This endpoint allows authorized delivery administrators to update the status of a pack to "sent."
    It requires a valid JWT token in the request cookies for authentication and a pack ID in the request body.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the Pack object with the ID provided in the request body.
    - Returns an error message if the pack with the specified ID is not found.
    - Sets the `PStatus` field of the pack to True (representing sent).
    - Saves the updated pack object to the database.
    - Serializes the updated pack using the `PackSerializer` for converting it to a JSON format.
    - Returns a successful response containing the serialized data of the updated pack.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    POST localhost:8000/api/deliveryAdmin/packConfirming/

    Request Body:
        {
            "packID" : "1"
        }
    """
    
    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'delivery_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        pack = Pack.objects.filter(id=request.data['packID']).first()
        
        pack.DAdminID = Delivery_admin.objects.filter(id=payload['id']).first()
        pack.PStatus = True
        pack.save()
        
        serializer = PackSerializer(pack)

        return Response(serializer.data)


##########################################################################################


class sign_up_a_catering_admin(APIView):
    """_summary_
    
    Handles POST requests to create a new catering administrator account.

    This endpoint allows authorized super administrators (identified by a secret cipher) to create new catering 
    administrator accounts. It expects the catering administrator's details in the request body.


    POST localhost:8000/api/cateringAdmin/signUp/

    Request Body:
        {
            "CA_username": "CateringAdminUsername",
            "password": "CateringAdminUsername",
            "cipher": "importantHiddenCipherThatJustSuperAdminKnows"
        }
    """
    
    def post(self, request):
        try:
            if request.data['cipher'] == 'importantHiddenCipherThatJustSuperAdminKnows':
                serializer = Catering_adminSerializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response(serializer.data)
            else:
                return Response('Incorrect Credentials')
        except:
            return Response('Improper request body.')
 
    
class catering_admin_login(APIView):
    """_summary_
    
    Handles POST requests to authenticate a catering administrator.

    This endpoint allows catering administrators to log in to the application using their username and password.
    Upon successful login, it generates a JWT token with a one-minute expiration time and sets it as a cookie
    named 'jwt' in the response.

    - Retrieves username and password from the request body.
    - Attempts to find a CateringAdmin object matching the provided username.
    - Raises an `AuthenticationFailed` exception if the username is not found.
    - Verifies the password for the retrieved CateringAdmin object.
    - Raises an `AuthenticationFailed` exception if the password is incorrect.
    - Creates a payload with user ID, expiration time, and issued-at time.
    - Encodes the payload into a JWT token using the 'catering_admin_secret_code' and HS256 algorithm.
    - Sets the JWT token as a cookie named 'jwt' with the HttpOnly flag enabled for security.
    - Returns a response containing the generated JWT token in the body.

    Raises `AuthenticationFailed` exceptions for invalid username or password.

    
    POST localhost:8000/api/cateringAdmin/login/

    Request Body:
        {
            "username" : "CateringAdminUsername",
            "password" : "CateringAdminUsername"
        }
    """
    
    def post(self, request):
        CA_username = request.data['username']
        password = request.data['password']

        user = Catering_admin.objects.filter(CA_username=CA_username).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if user.password != password:
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.now(datetime.timezone.utc)
        }

        token = jwt.encode(payload, 'catering_admin_secret_code', algorithm='HS256') #.decode('utf-8')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }
        return response
    
    
class sign_up_a_delivery_admin(APIView):
    """_summary_
    Handles POST requests to create a new delivery administrator account.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to create new delivery administrator accounts. It expects the delivery administrator's details in the request body.

    The request body should contain the following fields for the new delivery administrator:

    - username (string)
    - password (string)

    Returns Response: A JSON response containing the serialized data of the newly created delivery administrator
    or an error response for invalid token, improper request body, or other exceptions.

    
    POST localhost:8000/api/cateringAdmin/signUpADeliveryAdmin/

    Request Body:
        {
            "DA_username": "DeliveryAdminUsername",
            "password": "DeliveryAdminPassword"
        }
    """
    
    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        serializer = Delivery_adminSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    

class see_all_delivery_admins(APIView):
    """_summary_
    
    Handles GET requests to retrieve all delivery administrators.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view a list of all existing delivery administrators in the system.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves all DeliveryAdmin objects from the database.
    - If no delivery admins are found, returns a response with an informative message.
    - Serializes the retrieved delivery admins using the `Delivery_adminSerializer` for converting them to a JSON format.
    - Returns a successful response containing the serialized data of all delivery admins.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/cateringAdmin/seeAllDeliveryAdmins/

    Request Body:
        None
    """
    
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        delivery_admins = Delivery_admin.objects.all()
        
        if not delivery_admins:
            response = Response()
            response.data = {'message': 'There is no delivery admin.'}
            return response       
    
        serializer = Delivery_adminSerializer(delivery_admins, many=True)
        return Response(serializer.data)
    
    
class see_a_spec_delivery_admin(APIView):
    """_summary_
    
    Handles GET requests to retrieve details of a specific delivery administrator.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view details of a particular delivery administrator based on their ID.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the DeliveryAdmin object with the ID provided in the request body.
    - Returns an error message if the delivery admin with the specified ID is not found.
    - Serializes the retrieved delivery admin using the `Delivery_adminSerializer` for converting it to a JSON format.
    - Returns a successful response containing the serialized data of the specific delivery admin.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/cateringAdmin/seeASpecDeliveryAdmin/

    Request Body:
        {
            "dID" : "1"
        }
    """
    
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        delivery_admin = Delivery_admin.objects.filter(id=request.data['dID']).first()
        
        if not delivery_admin:
            response = Response()
            response.data = {'message': 'There is no delivery admin with this id.'}
            return response       
    
        serializer = Delivery_adminSerializer(delivery_admin)
        return Response(serializer.data)
    

class delete_a_delivery_admin(APIView):
    """_summary_
    
    Handles DELETE requests to delete a delivery administrator.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to delete a specific delivery administrator.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the DeliveryAdmin object with the ID provided in the request body.
    - Returns an error message if the delivery admin with the specified ID is not found.
    - Deletes the retrieved delivery admin object.
    - Returns a successful response message upon deletion.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    DELETE localhost:8000/api/cateringAdmin/deleteADeliveryAdmin/

    Request Body:
        {
            "dID" : "1"
        }
    """
    
    def delete(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        delivery_admin = Delivery_admin.objects.filter(id=request.data['dID']).first()
        
        if not delivery_admin:
            response = Response()
            response.data = {'message': 'There is no delivery admin with this id.'}
            return response       
    
        delivery_admin.delete()
        return Response('delivery admin succsesfully deleted!')
    
    
class see_all_customers(APIView):
    """_summary_
    
    Handles GET requests to retrieve all customers.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view a list of all existing customers in the system.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves all Customer objects from the database.
    - Returns an informative response if no customers are found.
    - Serializes the retrieved customers using the `CustomerSerializer` for converting them to a JSON format.
    - Returns a successful response containing the serialized data of all customers.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.


    GET localhost:8000/api/cateringAdmin/seeAllCustomers/

    Request Body:
        None
    """
    
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        customers = Customer.objects.all()
        
        if not customers:
            return Response('There is no customer.')       
    
        serializer = CustomerSerializer(customers, many=True)
        return Response(serializer.data)
    
    
class see_a_spec_customer(APIView):
    """_summary_
    
    Handles GET requests to retrieve details of a specific customer.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view details of a particular customer based on their ID.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the Customer object with the ID provided in the request body.
    - Returns an error message if the customer with the specified ID is not found.
    - Serializes the retrieved customer using the `CustomerSerializer` for converting it to a JSON format.
    - Returns a successful response containing the serialized data of the specific customer.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/cateringAdmin/seeASpecCustomer/

    Request Body:
        {
            "customerID" : "2"
        }
    """
    
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        customer = Customer.objects.filter(id=request.data['customerID']).first()
        
        if not customer:
            return Response('There is no customer with this id.')       
    
        serializer = CustomerSerializer(customer)
        return Response(serializer.data)
    
    
class delete_a_customer(APIView):
    """_summary_
    
    Handles DELETE requests to delete a customer.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to delete a specific customer.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the Customer object with the ID provided in the request body.
    - Returns an error message if the customer with the specified ID is not found.
    - Deletes the retrieved customer object.
    - Returns a successful response message upon deletion.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    DELETE localhost:8000/api/cateringAdmin/deleteACustomer/

    Request Body:
        {
            "customerID" : "2"
        }
    """
    
    def delete(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        customer = Customer.objects.filter(id=request.data['customerID']).first()
        
        if not customer:
            response = Response()
            response.data = {'message': 'There is no customer with this id.'}
            return response       
    
        customer.delete()
        return Response('The customer succsesfully deleted!')
    
    
class add_a_food(APIView):
    """_summary_
    
    Handles POST requests to create a new food item.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to create new food items. The request body should contain the food details.

    - Authenticates the user using the JWT token in the request cookies.
    - Extracts the catering administrator ID from the decoded payload.
    - Copies the request data.
    - Adds the catering administrator ID to the request data with the key 'CAdminID'.
    - Validates the request data using the `FoodSerializer`.
    - Saves the new food item to the database upon successful validation.
    - Returns a successful response containing the serialized data of the new food item.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.


    POST localhost:8000/api/cateringAdmin/addAFood/

    Request Body:
        {
            "foodName": "foodName",
            "price": "15",
            "category": "a"
        }
        
        Or

        {
            "foodName": "anotherFoodName",
            "price": "10",
            "category": "b",
            "description": "food description..."
        }
    """
    
    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        data = request.data.copy()
        data['CAdminID'] = payload['id']
        serializer = FoodSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
    
class see_a_spec_food(APIView):
    """_summary_
    
    Handles GET requests to retrieve details of a specific food item.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view details of a particular food item based on its ID.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the Food object with the ID provided in the request body.
    - Returns an error message if the food item with the specified ID is not found.
    - Serializes the retrieved food item using the `FoodSerializer` for converting it to a JSON format.
    - Returns a successful response containing the serialized data of the specific food item.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/cateringAdmin/seeASpecFood/

    Request Body:
        {
            "foodID" : "1"
        }
    """
    
    def get(self, request):
        
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        food = Food.objects.filter(id=request.data['foodID']).first()
        
        if not food:
            return Response('There is no food with this id.')       
    
        serializer = FoodSerializer(food)
        return Response(serializer.data)
    

class delete_a_food(APIView):
    """_summary_
    
    Handles DELETE requests to delete a food item.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to delete a specific food item.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the Food object with the ID provided in the request body.
    - Returns an error message if the food item with the specified ID is not found.
    - Deletes the retrieved food item object.
    - Returns a successful response message upon deletion.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    DELETE localhost:8000/api/cateringAdmin/deleteAFood/

    Request Body:
        {
            "foodID" : "1"
        }
    """
    
    def delete(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        food = Food.objects.filter(id=request.data['foodID']).first()
        
        if not food:
            response = Response()
            response.data = {'message': 'There is no food with this id.'}
            return response       
    
        food.delete()
        return Response('The food succsesfully deleted!')
    

class see_all_orders(APIView):
    """_summary_
    
    Handles GET requests to retrieve a list of all orders.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view a list of all existing orders in the system.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves all Order objects from the database.
    - Returns an informative message if no orders are found.
    - Serializes the retrieved orders using the `OrderSerializer` for converting them to a JSON format.
    - Returns a successful response containing the serialized data of all orders.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/cateringAdmin/seeAllOrders/

    Request Body:
        None
    """
    
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        orders = Order.objects.all()
        
        if not orders:
            return Response('There is no order.')       
    
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)
    
    
class see_a_spec_order(APIView):
    """_summary_
    
    Handles GET requests to retrieve details of a specific order.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view details of a particular order based on its ID.

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the Order object with the ID provided in the request body.
    - Returns an error message if the order with the specified ID is not found.
    - Serializes the retrieved order using the `OrderSerializer` for converting it to a JSON format.
    - Returns a successful response containing the serialized data of the specific order.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/cateringAdmin/seeASpecOrder/

    Request Body:
        {
            "orderID" : "2"
        }
    """
    
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        order = Order.objects.filter(id=request.data['orderID']).first()
        
        if not order:
            return Response('There is no order with this id.')       
    
        serializer = OrderSerializer(order)
        return Response(serializer.data)
    

class confirm_acceptance_of_an_order(APIView):
    """_summary_
    
    Handles POST requests to confirm acceptance of an order by a catering administrator.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to confirm acceptance of an order. Upon confirmation, several actions occur:

    1. Authentication: The user's JWT token is verified for validity.
    2. Order Retrieval: The order with the ID provided in the request body is retrieved.
    3. Confirmation Check: It checks if the order has already been confirmed. If so, an appropriate message is returned.
    4. Food Retrieval: The Food object associated with the order is retrieved.
    5. Order Cost Calculation: The total cost of the order is calculated based on the food price and quantity.
    6. Order Status Update: The order's status is set to confirmed (OStatus=True) and checked (O_Status_Check=True).
    7. Pack Management:
        - A Pack object is searched for, matching the customer ID and order date.
        - If a Pack doesn't exist, a new one is created with the order's cost as the initial total cost.
        - The catering admin who confirmed the order (obtained from the payload) is assigned to the order (CAdminID).
        - The order is linked to the Pack object (packID).
    8. Data Persistence: The updated Order and potentially created Pack objects are saved to the database.
    9. Serialization and Response: The confirmed order details are serialized and returned in the response.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    POST localhost:8000/api/cateringAdmin/confirmAcceptanceOfAnOrder/

    Request Body:
        {
            "orderID" : "2"
        }
    """

    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')   
    
        order = Order.objects.filter(id=request.data['orderID']).first()

        if not order:
            return Response("There is no order with that id.")

        if order.O_Status_Check == True:
            return Response('order has been checked.')
        
        food = Food.objects.filter(id=order.foodID.id).first()

        order_cost = food.price * order.quantity
        order.OStatus = True
        order.O_Status_Check = True

        pack = Pack.objects.filter(customerID=order.customerID.id).filter(orderDate=order.orderDate).first()

        if not pack:
            pack = Pack(
                customerID = order.customerID,
                orderDate = order.orderDate,
                totalCost = order_cost,
            )
            pack.save()
            order.CAdminID = Catering_admin.objects.filter(id=payload['id']).first()
            order.packID = pack
            order.save()
            serializer = OrderSerializer(order)
            return Response(serializer.data)
        
        pack.totalCost += order_cost
        order.CAdminID = Catering_admin.objects.filter(id=payload['id']).first()
        order.packID = pack
        pack.save()
        order.save()
        
        serializer = OrderSerializer(order)
        return Response(serializer.data)

        
class deny_acceptance_of_an_order(APIView):
    """_summary_
    
    Handles POST requests to deny acceptance of an order by a catering administrator.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to deny acceptance of an order. Upon denial:

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the Order object with the ID provided in the request body.
    - Returns an error message if the order is not found.
    - Returns an error message if the order has already been checked.
    - Retrieves the Food object associated with the order.
    - Retrieves the Customer object associated with the order.
    - Calculates the order cost based on food price and quantity.
    - Updates the customer's credit by adding the order cost back.
    - Sets the order's status to checked (O_Status_Check=True).
    - Assigns the catering admin who denied the order (from the payload) to the order (CAdminID).
    - Saves the Order and Customer objects.
    - Serializes the updated Order object and returns it in the response.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    POST localhost:8000/api/cateringAdmin/denyAcceptanceOfAnOrder/

    Request Body:
        {
            "orderID" : "2"
        }
    """

    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')  
        
        order = Order.objects.filter(id=request.data['orderID']).first()

        if not order:
            return Response("There is no order with that id.")

        if order.O_Status_Check == True:
            return Response('order has already been checked.')
        
        food = Food.objects.filter(id=order.foodID.id).first()
        
        customer = Customer.objects.filter(id=order.customerID.id).first()

        order_cost = food.price * order.quantity
        customer.C_credit += order_cost
        order.O_Status_Check = True
        order.CAdminID = Catering_admin.objects.filter(id=payload['id']).first()

        
        customer.save()
        order.save()
        
        serializer = OrderSerializer(order)
        return Response(serializer.data)
    
    
class see_all_unchecked_orders(APIView):
    """_summary_
    
    Handles GET requests to retrieve a list of all unchecked orders.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view a list of all orders that have not yet been checked (O_Status_Check=False). 

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves all Order objects where O_Status_Check is False (unchecked).
    - Returns a message if there are no unchecked orders.
    - Serializes the list of Order objects and returns them in the response.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/cateringAdmin/seeAllUncheckedOrders/

    Request Body:
        None
    """

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')  
        
        orders = Order.objects.filter(O_Status_Check=False).all()

        if not orders:
           return Response("All orders have been checked.")
            
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)

    
class see_all_checked_orders(APIView):
    """_summary_
    
    Handles GET requests to retrieve a list of all checked orders.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view a list of all orders that have been checked (O_Status_Check=True). 

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves all Order objects where O_Status_Check is True (checked).
    - Returns a message if there are no checked orders.
    - Serializes the list of Order objects and returns them in the response.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/cateringAdmin/seeAllCheckedOrders/

    Request Body:
        None
    """

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')  
        
        orders = Order.objects.filter(O_Status_Check=True).all()

        if not orders:
            return Response("There is no checked order.")
            
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)
    

class see_All_packs_Ca(APIView):
    """_summary_
    
    Handles GET requests to retrieve a list of all packs.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view a list of all Pack objects in the system. 

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves all Pack objects.
    - Returns a message if there are no packs.
    - Serializes the list of Pack objects and returns them in the response.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/cateringAdmin/seeAllPacks/

    Request Body:
        None
    """
    
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        packs = Pack.objects.all()
        
        if not packs:
            return Response('There is no pack.')

        serializer = PackSerializer(packs, many=True)
        return Response(serializer.data)

        
class see_a_spec_pack_Ca(APIView):
    """_summary_
    
    Handles GET requests to retrieve details of a specific pack by ID.

    This endpoint allows authorized catering administrators (identified by a valid JWT token in request cookies)
    to view details of a specific Pack object based on its ID provided in the request data. 

    - Authenticates the user using the JWT token in the request cookies.
    - Retrieves the Pack object with the ID provided in the request data.
    - Returns a message if the pack is not found.
    - Serializes the retrieved Pack object and returns it in the response.

    Raises `AuthenticationFailed` exceptions if the token is missing or invalid.

    
    GET localhost:8000/api/cateringAdmin/seeASpecPack/

    Request Body:
        {
            "packID" : "1"
        }
    """
    
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'catering_admin_secret_code', algorithms=['HS256'])
        except:
            raise AuthenticationFailed('Unauthenticated!')
        
        pack = Pack.objects.filter(id=request.data['packID']).first()
        
        if not pack:
            return Response('There is no pack whit that ID.')

        serializer = PackSerializer(pack)
        return Response(serializer.data)
    

