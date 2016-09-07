from django.conf import urls

from rest_framework import routers

from . import views

router = routers.DefaultRouter()
router.register(r'otp', views.OTPVerifyViewset, base_name='otp')

urlpatterns = [
    urls.url(r'^otp/login/$', views.OTPLoginView.as_view(), name='rest_login'),
    urls.url(r'^', urls.include(router.urls)),
    urls.url(
        r'^otp/logout/$', views.OTPLogoutView.as_view(), name='rest_logout'),

]
