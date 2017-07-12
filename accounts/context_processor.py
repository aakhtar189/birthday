import datetime

from django.contrib.auth.models import User


# def employee_obj_image(request):
#     if request.user.is_authenticated():
#         user_obj = User.objects.get(id=request.user.id)
#         employee, create = Employees.objects.get_or_create(user=user_obj)
#         return {'employee_obj': employee.image}
#     else:
#         return {}
