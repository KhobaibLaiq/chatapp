from django.shortcuts import render,redirect
from .models import *
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError


@login_required(login_url="/login/")
def index(request):
    users = User.objects.exclude(username=request.user.username)
    context = {'allusers': users}
    return render(request, 'index.html', context) 

@login_required(login_url="/login/")
def send_message(request, receiver_username):
    receiver = User.objects.get(username=receiver_username)  
    
    if request.method == 'POST':
        content = request.POST.get('content')
        receiver = User.objects.get(username=receiver_username)
        if content and receiver != request.user:
            message = Message(sender=request.user, receiver=receiver, content=content)
            message.save()
    received_messages = Message.objects.filter(sender=receiver, receiver=request.user).order_by('-timestamp') | \
                         Message.objects.filter(sender=request.user, receiver=receiver).order_by('-timestamp')
    context = {'received_messages': received_messages, 'receiver': receiver}
    return render(request, 'chat.html', context)

@login_required(login_url="/login/")
def edit_message(request, message_id):
    message = Message.objects.get(pk=message_id)

    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            message.content = content
            message.edited = True 
            message.save()
            return redirect('send_message', message.receiver.username) 

    context = {'message': message}
    return render(request, 'edit_message.html', context)

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = User.objects.filter(username =username)
        # Validate password
        try:
            validate_password(password)
        except ValidationError as error:
            messages.error(request, error)
            return redirect('signup')
        #check if username already taken
        if user.exists():
            messages.info(request, "username taken already")
            return redirect('signup.html')
        
        user = User.objects.create(
            username = username,
            email = email,
        )
        # Password Hashing
        user.set_password(password)
        user.save()
        messages.info(request, 'account created successfully!')
        return redirect('/login/')
        
    return render(request,'signup.html')

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        
        if not User.objects.filter(username = username).exists():
            messages.error(request, 'Invalid Username')
            return redirect('/login/')
        #now check username and password
        user = authenticate(username = username , password = password)
        if user is None:
            messages.error(request, 'Incorrect Password!')          
            return redirect('/login/')
        
        else:
            login(request, user)
            return redirect('/')
        
    return render(request,'login.html')
            

@login_required(login_url="/login/")
def user_logout(request):
    logout(request)
    return redirect('/login/')

