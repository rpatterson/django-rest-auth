"""
Tests for `django-otp` integration.
"""

from django import test
from django.contrib import auth
from django.conf import urls

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
class OTPTests(test.TestCase, test_base.BaseAPITestCase):
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
