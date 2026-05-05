from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.views import LoginView, LogoutView
from django.shortcuts import redirect, render
from django.urls import reverse_lazy

from .forms import LoginForm, RegisterForm


class UserLoginView(LoginView):
    template_name = 'accounts/login.html'
    authentication_form = LoginForm


class UserLogoutView(LogoutView):
    next_page = reverse_lazy('accounts:login')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, 'Welcome to WebGuard. Your account is ready.')
            return redirect('dashboard:home')
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})
