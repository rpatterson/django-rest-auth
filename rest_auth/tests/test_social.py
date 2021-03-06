import json

from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.contrib.sites.models import Site

from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.facebook.provider import GRAPH_API_URL
import responses

from rest_framework import status

from .test_base import BaseAPITestCase


@override_settings(ROOT_URLCONF="tests.urls")
class TestSocialAuth(BaseAPITestCase):

    USERNAME = 'person'
    PASS = 'person'
    EMAIL = "person1@world.com"
    REGISTRATION_DATA = {
        "username": USERNAME,
        "password1": PASS,
        "password2": PASS,
        "email": EMAIL
    }

    def setUp(self):
        self.init()

        social_app = SocialApp.objects.create(
            provider='facebook',
            name='Facebook',
            client_id='123123123',
            secret='321321321',
        )

        twitter_social_app = SocialApp.objects.create(
            provider='twitter',
            name='Twitter',
            client_id='11223344',
            secret='55667788',
        )

        site = Site.objects.get_current()
        social_app.sites.add(site)
        twitter_social_app.sites.add(site)
        self.graph_api_url = GRAPH_API_URL + '/me'
        self.twitter_url = 'http://twitter.com/foobarme'

    @responses.activate
    def test_failed_social_auth(self):
        # fake response
        responses.add(
            responses.GET,
            self.graph_api_url,
            body='',
            status=400,
            content_type='application/json'
        )

        payload = {
            'access_token': 'abc123'
        }
        self.post(self.fb_login_url, data=payload, status_code=400)

    @responses.activate
    def test_social_auth(self):
        # fake response for facebook call
        resp_body = {
            "id": "123123123123",
            "first_name": "John",
            "gender": "male",
            "last_name": "Smith",
            "link": "https://www.facebook.com/john.smith",
            "locale": "en_US",
            "name": "John Smith",
            "timezone": 2,
            "updated_time": "2014-08-13T10:14:38+0000",
            "username": "john.smith",
            "verified": True
        }

        responses.add(
            responses.GET,
            self.graph_api_url,
            body=json.dumps(resp_body),
            status=200,
            content_type='application/json'
        )

        users_count = get_user_model().objects.all().count()
        payload = {
            'access_token': 'abc123'
        }

        self.post(self.fb_login_url, data=payload, status_code=200)
        self.assertIn('key', self.response.json.keys())
        self.assertEqual(get_user_model().objects.all().count(), users_count + 1)

        # make sure that second request will not create a new user
        self.post(self.fb_login_url, data=payload, status_code=200)
        self.assertIn('key', self.response.json.keys())
        self.assertEqual(get_user_model().objects.all().count(), users_count + 1)

    def _twitter_social_auth(self):
        # fake response for twitter call
        resp_body = {
            "id": "123123123123",
        }

        responses.add(
            responses.GET,
            'https://api.twitter.com/1.1/account/verify_credentials.json',
            body=json.dumps(resp_body),
            status=200,
            content_type='application/json'
        )

        users_count = get_user_model().objects.all().count()
        payload = {
            'access_token': 'abc123',
            'token_secret': '1111222233334444'
        }

        self.post(self.tw_login_url, data=payload)

        self.assertIn('key', self.response.json.keys())
        self.assertEqual(get_user_model().objects.all().count(), users_count + 1)

        # make sure that second request will not create a new user
        self.post(self.tw_login_url, data=payload, status_code=200)
        self.assertIn('key', self.response.json.keys())
        self.assertEqual(get_user_model().objects.all().count(), users_count + 1)

    @responses.activate
    @override_settings(SOCIALACCOUNT_AUTO_SIGNUP=True)
    def test_twitter_social_auth(self):
        self._twitter_social_auth()

    @responses.activate
    @override_settings(SOCIALACCOUNT_AUTO_SIGNUP=False)
    def test_twitter_social_auth_without_auto_singup(self):
        self._twitter_social_auth()

    @responses.activate
    def test_twitter_social_auth_request_error(self):
        # fake response for twitter call
        resp_body = {
            "id": "123123123123",
        }

        responses.add(
            responses.GET,
            'https://api.twitter.com/1.1/account/verify_credentials.json',
            body=json.dumps(resp_body),
            status=400,
            content_type='application/json'
        )

        users_count = get_user_model().objects.all().count()
        payload = {
            'access_token': 'abc123',
            'token_secret': '1111222233334444'
        }

        self.post(self.tw_login_url, data=payload, status_code=400)
        self.assertNotIn('key', self.response.json.keys())
        self.assertEqual(get_user_model().objects.all().count(), users_count)

    @responses.activate
    def test_twitter_social_auth_no_view_in_context(self):
        # fake response for twitter call
        resp_body = {
            "id": "123123123123",
        }

        responses.add(
            responses.GET,
            'https://api.twitter.com/1.1/account/verify_credentials.json',
            body=json.dumps(resp_body),
            status=400,
            content_type='application/json'
        )

        users_count = get_user_model().objects.all().count()
        payload = {
            'access_token': 'abc123',
            'token_secret': '1111222233334444'
        }

        self.post(self.tw_login_no_view_url, data=payload, status_code=400)
        self.assertEqual(get_user_model().objects.all().count(), users_count)

    @responses.activate
    def test_twitter_social_auth_no_adapter(self):
        # fake response for twitter call
        resp_body = {
            "id": "123123123123",
        }

        responses.add(
            responses.GET,
            'https://api.twitter.com/1.1/account/verify_credentials.json',
            body=json.dumps(resp_body),
            status=400,
            content_type='application/json'
        )

        users_count = get_user_model().objects.all().count()
        payload = {
            'access_token': 'abc123',
            'token_secret': '1111222233334444'
        }

        self.post(self.tw_login_no_adapter_url, data=payload, status_code=400)
        self.assertEqual(get_user_model().objects.all().count(), users_count)

    @responses.activate
    @override_settings(
        ACCOUNT_EMAIL_VERIFICATION='mandatory',
        ACCOUNT_EMAIL_REQUIRED=True,
        REST_SESSION_LOGIN=False,
        ACCOUNT_EMAIL_CONFIRMATION_HMAC=False
    )
    def test_edge_case(self):
        resp_body = {
            "id": "123123123123",
            "first_name": "John",
            "gender": "male",
            "last_name": "Smith",
            "link": "https://www.facebook.com/john.smith",
            "locale": "en_US",
            "name": "John Smith",
            "timezone": 2,
            "updated_time": "2014-08-13T10:14:38+0000",
            "username": "john.smith",
            "verified": True,
            "email": self.EMAIL
        }

        responses.add(
            responses.GET,
            self.graph_api_url,
            body=json.dumps(resp_body),
            status=200,
            content_type='application/json'
        )

        # test empty payload
        self.post(self.register_url, data={}, status_code=400)
        self.post(
            self.register_url,
            data=self.REGISTRATION_DATA,
            status_code=201
        )
        new_user = get_user_model().objects.latest('id')
        self.assertEqual(new_user.username, self.REGISTRATION_DATA['username'])

        # verify email
        email_confirmation = new_user.emailaddress_set.get(email=self.EMAIL)\
            .emailconfirmation_set.order_by('-created')[0]
        self.post(
            self.veirfy_email_url,
            data={"key": email_confirmation.key},
            status_code=status.HTTP_200_OK
        )

        self._login()
        self._logout()

        payload = {
            'access_token': 'abc123'
        }

        self.post(self.fb_login_url, data=payload, status_code=200)
        self.assertIn('key', self.response.json.keys())

    @responses.activate
    @override_settings(
        REST_USE_JWT=True
    )
    def test_jwt(self):
        resp_body = '{"id":"123123123123","first_name":"John","gender":"male","last_name":"Smith","link":"https:\\/\\/www.facebook.com\\/john.smith","locale":"en_US","name":"John Smith","timezone":2,"updated_time":"2014-08-13T10:14:38+0000","username":"john.smith","verified":true}'  # noqa
        responses.add(
            responses.GET,
            self.graph_api_url,
            body=resp_body,
            status=200,
            content_type='application/json'
        )

        users_count = get_user_model().objects.all().count()
        payload = {
            'access_token': 'abc123'
        }

        self.post(self.fb_login_url, data=payload, status_code=200)
        self.assertIn('token', self.response.json.keys())
        self.assertIn('user', self.response.json.keys())

        self.assertEqual(get_user_model().objects.all().count(), users_count + 1)
