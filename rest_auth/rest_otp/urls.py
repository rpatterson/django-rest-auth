import copy

from django.conf import urls

from rest_framework import routers

from . import views


class EntityBodyRouter(routers.DefaultRouter):
    """
    The default router without for HTTP methods that ignore entity bodies.
    """

    # Deep copy of the default routes so we can modify the mappings
    # without changing the default routes.
    routes = copy.deepcopy(routers.DefaultRouter.routes)
    for route in routes:
        if isinstance(route, routers.Route):
            # Remove default routes for HTTP methods for which entity bodies
            # may be ignored and thus may be stripped by various proxies.
            route.mapping.pop('get', None)
            route.mapping.pop('delete', None)

router = routers.DefaultRouter()
router.register(r'otp', views.OTPVerifyViewset, base_name='otp')

body_router = EntityBodyRouter()
body_router.register(r'otp', views.OTPProvisionViewset, base_name='otp')

urlpatterns = [
    urls.url(r'^otp/login/$', views.OTPLoginView.as_view(), name='rest_login'),
    urls.url(r'^', urls.include(router.urls)),
    urls.url(r'^', urls.include(body_router.urls)),
    urls.url(
        r'^otp/logout/$', views.OTPLogoutView.as_view(), name='rest_logout'),

]
