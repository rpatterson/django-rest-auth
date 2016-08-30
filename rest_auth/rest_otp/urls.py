from django.conf import urls

from rest_framework import routers

from . import views

router = routers.DefaultRouter()
router.register(r'otp-verify', views.OTPVerifyViewset, base_name='otp-verify')

urlpatterns = [
    urls.url(r'^login/$', views.OTPLoginView.as_view(), name='rest_login'),
    urls.url(r'^', urls.include(router.urls)),
    urls.url(r'^logout/$', views.OTPLogoutView.as_view(), name='rest_logout'),

]
