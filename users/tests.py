from io import StringIO

from django.contrib.auth.models import Group
from django.core.management import call_command
from rest_framework import status
from rest_framework.test import APITestCase
from django.conf import settings


# Create your tests here.
class DataBaseTestCase(APITestCase):

    def setUp(self):
        self.call_command()
        self.username_structure = 'estracto_volcan'
        self.password_default = settings.PASSWORD_DEFAULT

    def get_username(self, type_user):
        return f'{self.username_structure}_{type_user}'

    def get_username_superadmin(self):
        return self.get_username(type_user='superadmin')

    def get_email_superadmin(self):
        return self.get_username_superadmin() + '@yopmail.com'

    def get_username_operator(self, num: int = 1):
        return self.get_username(type_user=f'operator_{num}')

    def get_email_operator(self, num: int = 1):
        return self.get_username_operator(num=num) + '@yopmail.com'

    def call_command(self, *args, **kwargs):
        out = StringIO()
        call_command(
            "load_data_initial",
            *args,
            stdout=out,
            stderr=StringIO(),
            **kwargs,
        )
        return out.getvalue()


class AuthLoginTestCase(DataBaseTestCase):

    def setUp(self):
        super(AuthLoginTestCase, self).setUp()
        from django.contrib.auth.models import User, Group
        # create super user
        if not User.objects.filter(username=self.get_username_superadmin()).exists():
            from rest_framework_simplejwt.tokens import RefreshToken
            from users.models import Profile
            self.superadmin = User.objects.create_user(
                username=self.get_username_superadmin(),
                email=self.get_email_superadmin(),
                password=self.password_default, is_superuser=True)
            self.superadmin.save()
            profile = self.superadmin.profile
            profile.first_name = 'Admin'
            profile.last_name = 'Uno'
            profile.email = self.get_email_superadmin()
            profile.verification_email = True
            profile.role = Profile.SUPERADMIN
            profile.save()

            url_api = '/api/auth/login/'
            response = self.client.post(url_api, {
                'username': self.get_email_superadmin(),
                'password': self.password_default
            }, format='json')
            self.access_token = response.data['access']

    # def test_login_admin_with_email(self):
    #     """
    #         Test Login admin with email
    #     """
    #     from users.models import Profile
    #     from rest_framework.test import APIClient
    #     # Registrar un admin
    #     if not Profile.objects.filter(user__username=self.get_username_operator()).exists():
    #         client = APIClient()
    #         client.credentials(HTTP_AUTHORIZATION='Bearer {}'.format(self.access_token))
    #         url_api = '/api/auth/register/admin/'
    #         response = client.post(url_api, {
    #             "first_name": "Admin",
    #             "last_name": "Test",
    #             "second_last_name": "",
    #             "phone": "5555555576",
    #             "email": "coztyc.test.admin@yopmail.com",
    #             "password": "C4sc4Nu3c3s@"
    #         }, format='json')
    #         self.assertEqual(response.data['success'], True)
    #     self.admin_register = Profile.objects.get(user__username='coztyc.test.admin@yopmail.com')
    #
    #     # revisar si no se ha verificado el usuario, se hace la verificacion
    #     if not self.admin_register.verification_email:
    #         from users.models import ProfileVerification
    #         verification = ProfileVerification.objects.get(profile=self.admin_register,
    #                                                        type_verification=ProfileVerification.VERIFICATION_EMAIL)
    #
    #         import jwt
    #         from django.conf import settings
    #         token = jwt.encode({"code": verification.code,
    #                             "email": verification.data_verification,
    #                             }, settings.SECRET_KEY, algorithm="HS256")
    #
    #         url_api = '/api/auth/verification/code/admin/'
    #         response = self.client.post(url_api, {'token': token}, format='json')
    #         self.assertEqual(response.data['success'], True)
    #
    #     url_api = '/api/auth/login/'
    #     response = self.client.post(url_api, {
    #         'username': 'coztyc.test.admin@yopmail.com',
    #         'password': 'C4sc4Nu3c3s@'
    #     }, format='json')
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertTrue('access' in response.data)
