from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordResetForm, SetPasswordForm
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.core.mail import send_mail
from django.urls import reverse
from django.template.loader import render_to_string
from django.http import HttpResponseRedirect
# Create your views here.
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_decode

from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator



def home_view(request):
    return render(request,'home.html')

def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request,user)
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request,'signup.html',{'form':form})


def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('home')
    else:
        form  = AuthenticationForm()
    return render(request, 'login.html',{'form':form})

def logout_view(request):
    logout(request)
    return redirect('login')

def password_reset_view(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = User.objects.filter(email=email).first()
            if user is not None:
                subject = 'Password reset'
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                reset_url = request.build_absolute_uri(reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token}))
                message = f'You can reset your password here: {reset_url}'
                send_mail(subject, message, 'from@example.com', [email])
                messages.success(request, 'An email with password reset instructions has been sent.')
                return redirect('password_reset_done')
            else:
                messages.error(request, 'No user found with that email address.')
    else:
        form = PasswordResetForm()
    return render(request, 'password_reset.html', {'form': form})



def password_reset_done_view(request):
    return render(request, 'password_reset_done.html')

def password_reset_confirm_view(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Your password has been reset successfully.')
                return redirect('password_reset_complete')
        else:
            form = SetPasswordForm(user)
        return render(request, 'password_reset_confirm.html', {'form': form})
    else:
        messages.error(request, 'The password reset link is invalid. Please request a new one.')
        return redirect('password_reset')

def password_reset_complete_view(request):
    return render(request, 'password_reset_complete.html')