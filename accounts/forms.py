from __future__ import unicode_literals

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth import password_validation
from django.forms import FileInput

from accounts.models import PasswordResetAuth


class LoginForm(forms.Form):
    email = forms.EmailField(max_length=75, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

    def clean(self):
        cleaned_data = super(LoginForm, self).clean()
        email = cleaned_data.get("email", "")
        if not User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email address does not exists!")
        return cleaned_data


class ChangePasswordForm(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(ChangePasswordForm, self).__init__(*args, **kwargs)

    def clean_old_password(self):
        """
        Validates that the old_password field is correct.
        """
        old_password = self.cleaned_data["old_password"]

        if not self.user.check_password(old_password):
            raise forms.ValidationError("Your old password was entered incorrectly. Please enter it again.")

        return old_password

    def clean_confirm_password(self):
        new_password = self.cleaned_data.get('new_password')
        confirm_password = self.cleaned_data.get('confirm_password')

        if new_password and confirm_password:
            if new_password != confirm_password:
                raise forms.ValidationError("The two password fields didn't match.")

        password_validation.validate_password(confirm_password, self.user)

        return confirm_password

    def save(self, commit=True):
        password = self.cleaned_data["new_password"]
        self.user.set_password(password)

        if commit:
            self.user.save()

        return self.user


class ForgetPasswordForm(forms.Form):
    registered_email = forms.EmailField(max_length=75, widget=forms.TextInput(attrs={'class': 'form-control'}))

    def clean_registered_email(self):
        cleaned_data = super(ForgetPasswordForm, self).clean()
        registered_email = cleaned_data.get("registered_email", "")
        if not User.objects.filter(email=registered_email).exists():
            raise forms.ValidationError("Account doesn't exist with this email id. Please try again!")
        return registered_email


class ResetPasswordForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

    def __init__(self, *args, **kwargs):
        self.token = kwargs.pop('token', None)
        super(ResetPasswordForm, self).__init__(*args, **kwargs)

    def clean_confirm_password(self):
        cleaned_data = super(ResetPasswordForm, self).clean()
        new_password = cleaned_data.get("new_password", "")
        confirm_password = cleaned_data.get("confirm_password", "")

        if new_password != confirm_password:
            raise forms.ValidationError("Password did not match. Make it correct.")

        if not PasswordResetAuth.objects.filter(token=self.token, is_expired=False).exists():
            raise forms.ValidationError("Either you are not an identified user or token has been expired. So please click on forget password.")

        return confirm_password