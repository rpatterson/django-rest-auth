import django_otp

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
        authenticators = request.authenticators
        try:
            request.authenticators = self.get_authenticators()

            if request.successful_authenticator is None:
                # None of the stacked authenticators authenticated, so we
                # don't either.  Allow moving onto to any other
                # authentication_classes outside our own
                return

            if not hasattr(request.user, 'is_verified'):
                raise AssertionError(
                    'The OTPMiddleware is required but has not been applied.')

            if (
                    self.require_devices or
                    django_otp.user_has_device(request.user)):
                    if request.user.is_verified():
                        return (request.user, request.auth)
                    else:
                        raise exceptions.AuthenticationFailed(
                            'The user has not been verified through OTP.')
        finally:
            request.authenticators = authenticators

        # OTP verification not required
        return (request.user, request.auth)


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
