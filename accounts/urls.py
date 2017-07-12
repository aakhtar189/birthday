from django.conf.urls import url
from accounts import views as account_views

urlpatterns = [
    url(r'^login/$', account_views.login_user, name="login_user"),
    url(r'^logout/$', account_views.logout_user, name="logout_user"),
    url(r'^change-password/$', account_views.change_password, name='change_password'),
    url(r'^forget-password/$', account_views.forget_password, name='forget_password'),
    url(r'^reset-password/(?P<token>[a-zA-Z0-9]*)/$', account_views.user_reset_password, name="user_reset_password"),

]