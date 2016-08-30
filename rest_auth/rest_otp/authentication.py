import django_otp

from rest_framework.request import clone_request
from rest_framework import authentication
from rest_framework import exceptions


class OTPStackedAuthentication(authentication.BaseAuthentication):
    """
    Authenticate using stacked classes and then enforce OTP verification.
    """

    authentication_classes = None
    require_devices = False

    def get_authenticators(self):
        """
        Instantiates and returns the list of stacked authenticators.
        """
        return [auth() for auth in self.authentication_classes]

    def authenticate(self, request):
        """
        Enforce OTP verification on stacked authenticators.
        """
        self.request = clone_request(request, request.method)
        self.request.authenticators = self.get_authenticators()

        if self.request.successful_authenticator is None:
            # None of the stacked authenticators authenticated, so we don't
            # either.  Allow moving onto to any other authentication_classes
            # outside our own
            return

        if not hasattr(self.request.user, 'is_verified'):
            raise AssertionError(
                'The OTPMiddleware is required but has not been applied.')

        if (
                self.require_devices or
                django_otp.user_has_device(self.request.user)):
                if self.request.user.is_verified():
                    return (self.request.user, self.request.auth)
                else:
                    raise exceptions.AuthenticationFailed(
                        'The user has not been verified through OTP.')

        # OTP verification not required
        return (self.request.user, self.request.auth)


class OTPSessionAuthentication(OTPStackedAuthentication):
    """
    Enforce OTP verification on Django session authentication.
    """

    authentication_classes = (authentication.SessionAuthentication, )


class OTPRequiredSessionAuthentication(OTPSessionAuthentication):
    """
    Enforce OTP verification on Django session authentication.
    """

    require_devices = True
