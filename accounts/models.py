from django.db import models


class PasswordResetAuth(models.Model):
    email = models.EmailField(max_length=75)
    token = models.CharField(max_length=11)
    is_expired = models.BooleanField(default=False)

    def __str__(self):
        return u'%s' % self.email