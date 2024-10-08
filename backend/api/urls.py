from django.urls import path
from .views import *


urlpatterns = [
	path('', Greeting.as_view(), name="greeting"),
	path('foods/', see_all_foods.as_view(), name="see_all_foods"),
	path('customer/signUp/', sign_up_a_customer.as_view(), name="sign_up_a_customer"),
	path('customer/login/', customer_login.as_view(), name="customer_login"),
	path('customer/info/', see_a_customer_info.as_view(), name="see_a_customer_info"),
	path('customer/update/', edit_a_customer_info.as_view(), name="edit_a_customer_info"),
	path('customer/charge/', charge_a_customer_credit.as_view(), name="charge_a_customer_credit"),
	path('customer/order/', add_an_order.as_view(), name="add_an_order"),
	path('customer/orderUpdate/', edit_a_customer_order.as_view(), name="edit_a_customer_order"),
	path('customer/ordersInfo/', see_a_customer_all_orders.as_view(), name="see_a_customer_all_orders"),
	path('customer/logout/', customer_logout.as_view(), name="customer_logout"),
	path('deliveryAdmin/login/', delivery_admin_login.as_view(), name="delivery_admin_login"),
	path('deliveryAdmin/packs/', see_All_packs.as_view(), name="see_All_packs"),
	path('deliveryAdmin/pack/', see_a_spec_pack.as_view(), name="see_a_spec_pack"),
	path('deliveryAdmin/packConfirming/', turn_a_pack_status_to_sent.as_view(), name="turn_a_pack_status_to_sent"),
	path('cateringAdmin/signUp/', sign_up_a_catering_admin.as_view(), name="sign_up_a_catering_admin"),
	path('cateringAdmin/login/', catering_admin_login.as_view(), name="catering_admin_login"),
	path('cateringAdmin/signUpADeliveryAdmin/', sign_up_a_delivery_admin.as_view(), name="sign_up_a_delivery_admin"),
	path('cateringAdmin/seeAllDeliveryAdmins/', see_all_delivery_admins.as_view(), name="see_all_delivery_admins"),
	path('cateringAdmin/seeASpecDeliveryAdmin/', see_a_spec_delivery_admin.as_view(), name="see_a_spec_delivery_admin"),
	path('cateringAdmin/deleteADeliveryAdmin/', delete_a_delivery_admin.as_view(), name="delete_a_delivery_admin"),
	path('cateringAdmin/seeAllCustomers/', see_all_customers.as_view(), name="see_all_customers"),
	path('cateringAdmin/seeASpecCustomer/', see_a_spec_customer.as_view(), name="see_a_spec_customer"),
	path('cateringAdmin/deleteACustomer/', delete_a_customer.as_view(), name="delete_a_customer"),
	path('cateringAdmin/addAFood/', add_a_food.as_view(), name="add_a_food"),
	path('cateringAdmin/seeASpecFood/', see_a_spec_food.as_view(), name="see_a_spec_food"),
	path('cateringAdmin/deleteAFood/', delete_a_food.as_view(), name="delete_a_food"),
	path('cateringAdmin/seeAllOrders/', see_all_orders.as_view(), name="see_all_orders"),
	path('cateringAdmin/seeASpecOrder/', see_a_spec_order.as_view(), name="see_a_spec_order"),
	path('cateringAdmin/confirmAcceptanceOfAnOrder/', confirm_acceptance_of_an_order.as_view(), name="confirm_acceptance_of_an_order"),
	path('cateringAdmin/denyAcceptanceOfAnOrder/', deny_acceptance_of_an_order.as_view(), name="deny_acceptance_of_an_order"),
	path('cateringAdmin/seeAllUncheckedOrders/', see_all_unchecked_orders.as_view(), name="see_all_unchecked_orders"),
	path('cateringAdmin/seeAllCheckedOrders/', see_all_checked_orders.as_view(), name="see_all_checked_orders"),
	path('cateringAdmin/seeAllCheckedOrders/', see_all_checked_orders.as_view(), name="see_all_checked_orders"),
	path('cateringAdmin/seeAllPacks/', see_All_packs_Ca.as_view(), name="see_All_packs_Ca"),
	path('cateringAdmin/seeASpecPack/', see_a_spec_pack_Ca.as_view(), name="see_a_spec_pack_Ca"),

]