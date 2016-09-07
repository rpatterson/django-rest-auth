from django.contrib import auth

from rest_framework import decorators
from rest_framework import response
from rest_framework import viewsets
from rest_framework import permissions
from rest_framework import authentication

from .. import views
from . import serializers


class OTPLoginView(views.LoginView):
    """
    Return the data needed for OTP verification on successful login.
    """

    otp_serializer_class = serializers.OTPTokenSerializer
    authentication_classes = (authentication.SessionAuthentication, )

    def get_response(self):
        """
        Add the data needed for OTP verification on successful login.
        """
        response = super(OTPLoginView, self).get_response()

        otp_serializer = self.otp_serializer_class(
            context=self.get_serializer_context())
        response.data['otp_devices'] = otp_serializer.form.fields[
            'otp_device'].widget.choices

        return response


class OTPVerifyViewset(viewsets.GenericViewSet):
    """
    Endpoints to verify OTP codes.
    """

    serializer_class = serializers.OTPTokenSerializer
    authentication_classes = (authentication.SessionAuthentication, )
    permission_classes = [permissions.IsAuthenticated]

    @decorators.list_route(methods=['post'])
    def verify(self, request, *args, **kwargs):
        """
        Perform the actual login if the serializer/form validates.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.form.get_user()
        # A minor hack to make django.contrib.auth.login happy
        user.backend = self.request.session[auth.BACKEND_SESSION_KEY]
        auth.login(self.request, user)

        return response.Response(dict(
            success="Successfully logged in."))


class OTPLogoutView(views.LogoutView):
    """
    Allow session authentication for logging out.
    """

    authentication_classes = (authentication.SessionAuthentication, )
