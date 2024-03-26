from django.urls import path
from .views import *
urlpatterns = [
    path('signup/', register, name="signup"),
    path('login/', user_login, name="login"),
    path('logout/', user_logout, name="logout"),
     path('', index, name='index'),
    path('send/<str:receiver_username>/', send_message, name='send_message'),
    path('edit/<int:message_id>/', edit_message, name='edit_message'),

]
