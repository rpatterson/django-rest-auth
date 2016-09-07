import base64
import binascii

from django.contrib import auth
from django.contrib.sites import shortcuts

from rest_framework import decorators
from rest_framework import response
from rest_framework import viewsets
from rest_framework import permissions
from rest_framework import authentication
from rest_framework import serializers as drf_serializers

from django_otp.plugins.otp_static import models
from two_factor import utils

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


class OTPProvisionViewset(OTPVerifyViewset):
    """
    Endpoints to provision and manage OTP devices.
    """

    serializer_class = serializers.NonEmptyLoginSerializer

    totp_device = dict(name='Authenticator App')
    backup_device = dict(name='Backup/Recovery Codes')
    number_of_tokens = 10

    @decorators.list_route(methods=['post'])
    def backup(self, request, *args, **kwargs):
        """
        Retreive the user's backup codes.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        backup_codes = request.user.staticdevice_set.values_list(
            'token_set__token', flat=True)
        return response.Response(dict(backup_codes=backup_codes))

    @decorators.list_route(methods=['post'])
    def provision(self, request, *args, **kwargs):
        """
        Provision TOTP and backup code devices.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if (
                request.user.totpdevice_set.exists() or
                request.user.staticdevice_set.exists()):
            raise drf_serializers.ValidationError(
                'OTP devices already exist for this user')

        totp_device = request.user.totpdevice_set.create(**self.totp_device)
        backup_device = request.user.staticdevice_set.create(
            **self.backup_device)
        backup_codes = [
            models.StaticToken.random_token()
            for n in range(self.number_of_tokens)]
        backup_device.token_set.bulk_create([
            models.StaticToken(token=token, device=backup_device)
            for token in backup_codes])

        b32key = base64.b32encode(binascii.unhexlify(totp_device.key))
        otpauth_url = utils.get_otpauth_url(
            accountname=request.user.email,
            issuer=shortcuts.get_current_site(self.request).name,
            secret=b32key, digits=totp_device.digits)

        return response.Response(dict(
            otpauth_url=otpauth_url, backup_codes=backup_codes))


class OTPLogoutView(views.LogoutView):
    """
    Allow session authentication for logging out.
    """

    authentication_classes = (authentication.SessionAuthentication, )
