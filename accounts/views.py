import json

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from django.utils.crypto import get_random_string
from django.core.mail import EmailMessage
from django.conf import settings

from accounts.models import PasswordResetAuth
from accounts.forms import LoginForm, ChangePasswordForm, ForgetPasswordForm, ResetPasswordForm


def homepage(request):
    if not request.user.is_authenticated():
        return redirect(reverse('login_user'))

    context = {}

    return render(request, "homepage.html", context)
     

def login_user(request):

    if request.user.is_authenticated():
        return redirect(reverse('homepage'))

    for_pass_form = ForgetPasswordForm(use_required_attribute=False)
    form = LoginForm(request.POST or None, use_required_attribute=False)

    if request.method == "POST":

        if form.is_valid():
            user_obj = User.objects.get(email=form.cleaned_data['email'])
            user = authenticate(username=user_obj.username, password=form.cleaned_data['password'])

            if user:
                if user.is_active:
                    login(request, user)

                    return redirect(reverse('homepage'))

                return redirect(reverse('login_user'))
            else:

                error_message = "* Password you entered is incorrect."

                return render(request, "accounts/login_user.html",{
                    "for_pass_form": for_pass_form,
                    "form": form,
                    "error_message": error_message,
                })
        else:
            for key, value in form.errors.items():
                tmp = {'key': key, 'error': value.as_text()}

            return render(request, "accounts/login_user.html",{
                "for_pass_form": for_pass_form,
                "form": form,
            })
    else:
        return render(request, "accounts/login_user.html", {
            "form": form,
            "for_pass_form": for_pass_form
        })


def logout_user(request):

    logout(request)
    return redirect(reverse('login_user'))


@login_required
def change_password(request):
    if request.is_ajax():

        user = User.objects.get(id=request.user.id)

        response = {"status": True, "errors": []}

        if request.method == "POST":
            form = ChangePasswordForm(request.user, request.POST or None, use_required_attribute=False)

            if form.is_valid():
                form.save()
                update_session_auth_hash(request, user)
                messages.add_message(request, messages.INFO, "Password has been updated successfully! Please Login again")

            else:
                response["status"] = False
                for key, value in form.errors.items():
                    tmp = {'key': key, 'error': value.as_text()}
                    response['errors'].append(tmp)

            return HttpResponse(json.dumps(response))


def forget_password(request):
    if request.is_ajax():

        response = {"status": True, "errors": [], "text": ""}

        if request.method == "POST":
            form = ForgetPasswordForm(request.POST or None, use_required_attribute=False)

            if form.is_valid():
                email = form.cleaned_data["registered_email"]
                token = get_random_string(length=11)
                PasswordResetAuth.objects.create(email=email, token=token)
                user = User.objects.get(email=email)
                first_name = user.first_name

                send_link = EmailMessage(
                    subject= 'Forgot Password',
                    body= "Hi {},".format(first_name)+ "\n \n" + "You recently requested to reset your password. Click the link below to reset it.\n \n" + settings.SITE_URL+"/account/reset-password/{}".format(token),
                    to=[email]
                )
                send_link.send()
                response["text"] = email

            else:
                response["status"] = False
                for key, value in form.errors.items():
                    tmp = {'key': key, 'error': value.as_text()}
                    response['errors'].append(tmp)

            return HttpResponse(json.dumps(response))


def user_reset_password(request, token):
    
    if request.user.is_authenticated():
        return redirect("/")

    form = ResetPasswordForm(request.POST or None, token=token, use_required_attribute=False)

    try:
        password_reset_auth = PasswordResetAuth.objects.get(token=token, is_expired=False)
    except PasswordResetAuth.DoesNotExist:
        raise Http404

    if request.method == "POST":
        if form.is_valid():
            user = User.objects.get(email=password_reset_auth.email)
            new_password = form.cleaned_data["new_password"]
            user.set_password(new_password)
            user.save()

            password_reset_auth.is_expired = True
            password_reset_auth.save()

            messages.add_message(request, messages.INFO, "Password has been reset successfully!")

            return redirect(reverse('login_user'))

    return render(request, "accounts/user_reset_password.html", {
        "form": form,
    })