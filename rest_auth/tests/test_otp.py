"""
Tests for `django-otp` integration.
"""

import base64
import binascii

from django import test
from django.contrib import auth
from django.conf import urls
from django.contrib.sites import shortcuts

from two_factor import utils

from rest_auth import views
from rest_auth.rest_otp import authentication
from rest_auth.rest_otp import urls as otp_urls

from . import urls as test_urls
from . import test_base


class OTPVerifiedUserDetailsView(views.UserDetailsView):
    """
    A view that requires authentication and verification.
    """

    authentication_classes = (
        authentication.OTPSessionAuthentication, )


urlpatterns = [
    urls.url(
        r'^user/$', OTPVerifiedUserDetailsView.as_view(),
        name='rest_otp_user_details'),
] + otp_urls.urlpatterns + test_urls.urlpatterns


@test.override_settings(ROOT_URLCONF="tests.test_otp")
class OTPTests(test_base.BaseAPITestCase):
    """
    Tests for `django-otp` integration.
    """

    USERNAME = 'person'
    PASS = 'person'
    EMAIL = "person1@world.com"

    def setUp(self):
        """
        Set up a user.
        """
        super(OTPTests, self).setUp()
        self.init()

        self.user = auth.get_user_model().objects.create(
            username=self.USERNAME, email=self.EMAIL)
        self.user.set_password(self.PASS)
        self.user.save()

    @test.modify_settings(MIDDLEWARE_CLASSES=dict(
        append='django_otp.middleware.OTPMiddleware'))
    def test_otp_login(self):
        """
        A user must enter a code when they've enabled MFA.
        """
        import django_otp
        from django_otp import oath

        # Verify initial conditions
        self.assertEqual(
            auth.get_user_model().objects.count(), 1, 'Wrong number of users')
        for device_model in django_otp.device_classes():
            self.assertFalse(
                device_model.objects.filter(user=self.user).exists(),
                'MFA devices exist before provisioning')
        # Authenticated view fails before logging in
        self.get('/user/', status_code=403)

        # Provision MFA devices
        totp_device = self.user.totpdevice_set.create(
            name='Authenticator App')
        self.assertEqual(
            self.user.totpdevice_set.filter(confirmed=True).count(),
            1,
            'Wrong number of app MFA devices after provisioning')

        # Login prompts for MFA code on login after provisioning
        login_response = self.post(
            '/otp/login/',
            data=dict(username=self.USERNAME, password=self.PASS),
            status_code=200)
        # Authenticated view fails before verification
        self.get('/user/', status_code=403)
        self.assertIn(
            'key', login_response.json,
            'Login response missing token')
        self.assertIn(
            'otp_devices', login_response.json,
            'Login response missing MFA/OTP devices')
        self.assertEqual(
            len(login_response.json['otp_devices']), 1,
            'Login response wrong number of MFA/OTP devices')

        # Invalid token returns an error
        otp_response = self.post(
            '/otp/verify/',
            data=dict(
                otp_device=login_response.json['otp_devices'][0][0],
                otp_token='FOOWRONGTOKEN'),
            status_code=400)
        self.assertIn(
            '__all__', otp_response.json,
            'Invalid MFA/OTP token verification response missing error')
        self.assertIn(
            'token', otp_response.json['__all__'][0].lower(),
            'Invalid MFA/OTP token verification response wrong message')

        # Send OTP verification code
        otp_response = self.post(
            '/otp/verify/',
            data=dict(
                otp_device=login_response.json['otp_devices'][0][0],
                otp_token=oath.TOTP(
                    totp_device.bin_key, totp_device.step, totp_device.t0,
                    totp_device.digits).token()),
            status_code=200)
        self.assertIn(
            'success', otp_response.json,
            'MFA/OTP token verification response missing success message')

        # Authenticated view works after verification
        self.get('/user/', status_code=200)

    def test_otp_login_wo_middleware(self):
        """
        The OTP middlware is required to use the authentication class.
        """
        self.post(
            '/otp/login/',
            data=dict(username=self.USERNAME, password=self.PASS),
            status_code=200)
        self.assertRaises(AssertionError, self.get, '/user/', status_code=500)

    @test.modify_settings(MIDDLEWARE_CLASSES=dict(
        append='django_otp.middleware.OTPMiddleware'))
    def test_otp_login_wo_device(self):
        """
        Authentication succeeds if the user has no OTP device.
        """
        self.post(
            '/otp/login/',
            data=dict(username=self.USERNAME, password=self.PASS),
            status_code=200)
        self.get('/user/', status_code=200)

    def test_otp_provision(self):
        """
        A POST with credentials will provision new OTP devices.
        """
        # Provision fails before login
        self.post(
            '/otp/provision/',
            data=dict(username=self.USERNAME, password=self.PASS),
            status_code=403)

        self.post(
            '/otp/login/',
            data=dict(username=self.USERNAME, password=self.PASS),
            status_code=200)

        # Requesting backup codes without posting login credentials fails
        provision_response = self.post(
            '/otp/provision/', data={}, status_code=400)
        provision_response = self.post(
            '/otp/provision/', status_code=400)

        provision_response = self.post(
            '/otp/provision/',
            data=dict(username=self.USERNAME, password=self.PASS),
            status_code=200)

        self.assertEqual(
            self.user.totpdevice_set.count(), 1,
            'Wrong number of TOTP devices')
        self.assertIn(
            'otpauth_url', provision_response.json,
            'Provision response missing the TOTP oath URL')
        totp_device = self.user.totpdevice_set.get()
        b32key = base64.b32encode(binascii.unhexlify(totp_device.key))
        otpauth_url = utils.get_otpauth_url(
            accountname=self.EMAIL, issuer=shortcuts.get_current_site(
                provision_response.request).name,
            secret=b32key, digits=totp_device.digits)
        self.assertEqual(
            provision_response.json['otpauth_url'], otpauth_url,
            'Wrong provision response TOTP oath URL')

        self.assertEqual(
            self.user.staticdevice_set.count(), 1,
            'Wrong number of backup code devices')
        self.assertEqual(
            self.user.staticdevice_set.get().token_set.count(), 10,
            'Wrong number of backup codes generated')
        self.assertIn(
            'backup_codes', provision_response.json,
            'Provision response missing backup codes')
        for token in self.user.staticdevice_set.get().token_set.all():
            self.assertIn(
                token.token, provision_response.json['backup_codes'],
                'Provision response missing backup code')

        # Cannot provision when already provisioned
        duplicate_response = self.post(
            '/otp/provision/',
            data=dict(username=self.USERNAME, password=self.PASS),
            status_code=400)
        self.assertEqual(
            self.user.totpdevice_set.count(), 1,
            'Wrong number of TOTP devices after duplicate provision')
        self.assertEqual(
            self.user.staticdevice_set.count(), 1,
            'Wrong number of backup code devices after duplicate provision')
        self.assertEqual(
            self.user.staticdevice_set.get().token_set.count(), 10,
            'Wrong number of backup codes after duplicate provision')
        self.assertIn(
            'already', duplicate_response.json[0],
            'Wrong duplicate provision response error message')

        # Requesting backup codes without posting login credentials fails
        self.post('/otp/backup/', data={}, status_code=400)
        self.post('/otp/backup/', status_code=400)

        backup_response = self.post(
            '/otp/backup/',
            data=dict(username=self.USERNAME, password=self.PASS),
            status_code=200)
        self.assertEqual(
            self.user.staticdevice_set.count(), 1,
            'Wrong number of backup code devices')
        self.assertEqual(
            self.user.staticdevice_set.get().token_set.count(), 10,
            'Wrong number of backup codes generated')
        self.assertIn(
            'backup_codes', backup_response.json,
            'Provision response missing the backup codes')
        for token in self.user.staticdevice_set.get().token_set.all():
            self.assertIn(
                token.token, backup_response.json['backup_codes'],
                'Provision response missing backup code')
