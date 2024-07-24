import base64

from django.core.cache import cache
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from rest_framework import status, exceptions
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken as JwtBlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

from common.utils import send_email, get_response_data_errors, get_data_email_general, code_generator, \
    handler_exception_general
from common.views import CustomViewSet, CustomViewSetWithPagination
from users.permissions import IsVerified, IsSuperadmin, IsChangePassword, IsAdministrator
from users.serializers import *
from users.utils import logout_users_process, set_code_and_validity_code, send_verification_2factor, \
    send_recover_password


class CustomTokenObtainPairView(CustomViewSet, TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        """
            Send code 2factor verification
        """
        try:
            username = request.data.get('username', 'hola')
            password = request.data.get('password', '-----')
            message_bytes = bytes(f"{username}:{password}", 'latin1')
            key_cache = base64.b64encode(message_bytes).decode('latin1')

            if key_cache not in cache:
                self.serializer = self.serializer_class(data=request.data)
                if self.serializer.is_valid():
                    response_data = self.serializer.validated_data
                    if 'user' in response_data:
                        user = response_data.pop('user')
                        if settings.ENABLE_SEND_EMAIL and settings.ENABLE_2FACTOR_AUTHENTICATION:
                            serializer = ResendCodeSerializer(data={'email': user.email, 'code': 'verification_2factor'})
                            serializer.is_valid()
                            verification = serializer.save()
                            self.resp = send_verification_2factor(verification)
                        else:
                            from rest_framework_simplejwt.tokens import RefreshToken
                            self.resp[1]['send_email'] = False
                            self.resp[1] = get_role_and_data(user, self.resp[1])
                            refresh = RefreshToken.for_user(user)
                            self.resp[1]['refresh'] = str(refresh)
                            self.resp[1]['access'] = str(refresh.access_token)
                    else:
                        response_data['RSP_CODIGO'] = '0000000000'
                        response_data['RSP_DESCRIPCION'] = 'Auth login success'
                        response_data['RSP_ERROR'] = 'OK'
                        cache.set(key_cache, response_data, 60 * 60 * 2)
                        self.make_response_success(data=response_data)
                else:
                    self.resp = get_response_data_errors(self.serializer.errors)
            else:
                self.make_response_success(data=cache.get(key_cache))
        except exceptions.AuthenticationFailed as e:
            self.resp = ['Usuario no activo o no encontrado', {'code': 'no_active_account'}, 400]
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        """
            With custom response
        """
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])
        response_data = {'RSP_SUCCESS'.lower(): True, 'RSP_CODIGO'.lower(): '00', 'RSP_DESCRIPCION'.lower(): 'ok'}
        for k, v in serializer.validated_data.items():
            response_data[k] = v
        return Response(response_data, status=status.HTTP_200_OK)


class CustomTokenVerifyView(TokenVerifyView):
    def post(self, request, *args, **kwargs):
        """
            With custom response
        """
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])
        response_data = {'RSP_SUCCESS'.lower(): True, 'RSP_CODIGO'.lower(): '00', 'RSP_DESCRIPCION'.lower(): 'ok'}
        for k, v in serializer.validated_data.items():
            response_data[k] = v
        return Response(response_data, status=status.HTTP_200_OK)


class RegisterAdminAPIView(CustomViewSet):
    permission_classes = (IsAuthenticated, IsVerified, IsAdministrator)
    serializer_class = RegisterAdminSerializer

    def perform_create(self, request, *args, **kwargs):
        """
            Create users admin
        """
        response_data = dict()
        profile = self.serializer.save()
        user = profile.user
        try:
            verification = ProfileVerification.objects.get(profile=profile,
                                                           data_verification=profile.user.email,
                                                           type_verification=VerificationType.VERIFICATION_EMAIL)
        except ProfileVerification.DoesNotExist:
            data = {
                'profile': profile,
                'type_verification': VerificationType.VERIFICATION_EMAIL,
                'data_verification': profile.user.email
            }
            verification = ProfileVerification.objects.create(**data)

        verification = set_code_and_validity_code(verification, True)

        d = get_data_email_general()

        d.update({
            "headerText": "Registrar administrador",
            "subheaderText": "",
            "titleText": f"¡Hola, {user.get_full_name()}!",
            "messageText": "Has sido registrado como administrador, "
                           "inicia sesión en Volcan Manager API con las siguientes credenciales:",
            "usernameText": user.username,
            "passwordText": request.data['password'],
            "host": settings.URL_BACKEND,
            "urlText": '',
            "code": verification.code if len(verification.code) <= 10 else '',
            'validityCode': timezone.localtime(verification.validity_code).strftime("%Y-%m-%d %H:%M:%S"),
            "buttonTitleText": "",
        })
        sending_response = send_email(None, [verification.data_verification, ], u'Registro en Volcan Manager API',
                                      'email/Email-General.html', {'data': d})
        if sending_response and verification and verification.validity_code:
            response_data['validity_code'] = verification.validity_code.isoformat()
            if settings.DEBUG:
                response_data['push_code'] = verification.code

        self.make_response_success(data=response_data)


class VerificationCodeAPIView(CustomViewSet):
    permission_classes = (AllowAny,)
    serializer_class = VerificationCodeSerializer

    def perform_create(self, request, *args, **kwargs):
        verification = self.serializer.save()
        profile = verification.profile
        if verification.type_verification == VerificationType.VERIFICATION_2FACTOR:
            response_data = get_role_and_data(profile.user, {})
            refresh = RefreshToken.for_user(profile.user)
            response_data['refresh'] = str(refresh)
            response_data['access'] = str(refresh.access_token)
        elif verification.type_verification == VerificationType.RECOVER_PASSWORD_EMAIL:
            profile.change_password = True
            profile.verification_email = True
            if profile.has_changed:
                profile.save()
            user = profile.user
            new_password = code_generator(characters=8)
            user.set_password(new_password)
            user.save()
            response_data = {'password': new_password, 'code': 'change-password', 'message': u'Cambiar contraseña'}
        elif verification.type_verification == VerificationType.VERIFICATION_EMAIL:
            profile.verification_email = True
            if profile.has_changed:
                profile.save()
            response_data = {'code': 'email_verified', 'message': 'Email verificado'}
        else:
            response_data = {'code': 'verification_code_invalid', 'message': 'Codigo no identificado'}
        self.make_response_success(data=response_data)


class ResendCodeAPIView(CustomViewSet):
    permission_classes = (AllowAny,)
    serializer_class = ResendCodeSerializer

    def create(self, request, *args, **kwargs):
        """
        Resend Code
        """
        try:
            self.serializer = self.serializer_class(data=request.data)
            if self.serializer.is_valid():
                verification = self.serializer.save()
                if settings.ENABLE_SEND_EMAIL:
                    type_verification = verification.type_verification
                    if type_verification == VerificationType.RECOVER_PASSWORD_EMAIL:
                        self.resp = send_recover_password(verification, security=True)
                    elif type_verification == VerificationType.VERIFICATION_2FACTOR \
                            and settings.ENABLE_2FACTOR_AUTHENTICATION:
                        self.resp = send_verification_2factor(verification)
                    elif type_verification == VerificationType.VERIFICATION_EMAIL:
                        self.resp = send_verification_2factor(verification)
                    else:
                        self.resp = ['La solicitud no pudo ser procesada', {'code': 'unknown'}, 400]
                else:
                    self.resp[0] = 'El sistema de envios de correos se encuentra desactivado. ' \
                                   'Favor de comunicarse con el administrador'
                    self.resp[1] = {'code': 'do_not_send_email', 'send_email': False}
                    self.resp[2] = 401
            else:
                self.resp = get_response_data_errors(self.serializer.errors)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()


class RecoverPasswordApiView(CustomViewSet):
    permission_classes = (AllowAny,)
    serializer_class = RecoverPasswordSerializer

    def create(self, request, *args, **kwargs):
        """
        Recover password
        """
        try:
            self.serializer = self.serializer_class(data=request.data)
            if self.serializer.is_valid():
                verification = self.serializer.save()
                if settings.ENABLE_SEND_EMAIL:
                    self.resp = send_recover_password(verification, security=True)
                else:
                    self.resp[0] = 'El sistema de envios de correos se encuentra desactivado. ' \
                                   'Favor de comunicarse con el administrador'
                    self.resp[1] = {'code': 'do_not_send_email', 'send_email': False}
                    self.resp[2] = 401
            else:
                self.resp = get_response_data_errors(self.serializer.errors)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()


class ChangePasswordApiView(CustomViewSet):
    permission_classes = (AllowAny,)
    serializer_class = ChangePasswordSerializer

    def create(self, request, *args, **kwargs):
        """
        Change password
        """
        try:
            self.serializer = self.serializer_class(data=request.data)
            if self.serializer.is_valid():
                response_data = self.serializer.save()
                self.make_response_success(data=response_data)
            else:
                self.resp = get_response_data_errors(self.serializer.errors)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()


class LogoutApiView(CustomViewSet):
    permission_classes = (IsAuthenticated, IsVerified)

    def create(self, request, *args, **kwargs):
        """
        Logout
        """
        try:
            self.resp = logout_users_process(request=request)
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()


# class LoginLogApiView(ViewSetMixin):
#     permission_classes = (IsAuthenticated, IsVerified)
#
#     def get(self, request, *args, **kwargs):
#         """
#             Get login log
#         """
#         import os
#         from pathlib import Path
#         from django.http import HttpResponse
#         base_dir = Path(__file__).resolve().parent.parent
#         file_name = 'login.log'
#         path_to_file = os.path.join(base_dir, "login.log")
#         file = open(path_to_file, "r")
#         response = HttpResponse(file, content_type='application/text')
#         response['Content-Disposition'] = 'attachment; filename=%s' % smart_str(file_name)
#         return response


class EmptyApiView(CustomViewSet):
    permission_classes = (IsAuthenticated, IsVerified, IsSuperadmin)

    def create(self, request, *args, **kwargs):
        """
        Empty user
        """
        response_message = ''
        response_data = dict()
        response_status = 201
        is_logout = True
        try:
            username = request.data.get('username')
            try:
                profile = Profile.objects.get(user__username=username)
            except Profile.DoesNotExist:
                if User.objects.filter(username=username).exists():
                    user = User.objects.get(username=username)
                    from types import SimpleNamespace
                    profile = SimpleNamespace(user=user, role=1, status='active', set_status=lambda slug: {})
                else:
                    profile = None
            if profile:
                if not WhiteListedToken.objects.filter(user=profile.user).exists():
                    is_logout = False
                    request.session['code'] = 'user_not_logged'
                    response_message = _(u'Usuario no tiene una sesión abierta.')
                    response_status = 400

            if is_logout:
                # token = get_access_token_from_request(request)
                whitelists = None

                if WhiteListedToken.objects.filter(user__username=username).exists():
                    whitelists = WhiteListedToken.objects.filter(user__username=username)

                if whitelists and whitelists.count():
                    for whitelisted in whitelists:
                        if whitelisted.refresh_token and OutstandingToken.objects.filter(
                                token=whitelisted.refresh_token).exists():
                            token = OutstandingToken.objects.get(token=whitelisted.refresh_token)
                            JwtBlacklistedToken.objects.create(token=token)

                    whitelists.delete()

                response_message = _('Existoso.')
            else:
                response_status = 400
        except Exception as e:
            response_message, response_data, response_status = handler_exception_general(__name__, e)
        finally:
            return self.get_response(response_message, response_data, response_status)


class ResetPasswordApiView(CustomViewSet):
    serializer_class = ResetPasswordSerializer
    permission_classes = (IsAuthenticated, IsVerified, IsSuperadmin)


class ProfileApiView(CustomViewSet):
    serializer_class = ProfileSerializer
    permission_classes = (IsAuthenticated, IsChangePassword)
    model_class = Profile
    field_pk = 'profile_id'
    http_method_names = ['get', 'options', 'head']

    def retrieve(self, request, *args, **kwargs):
        try:
            profile = request.user.profile
            self.serializer = self.get_one_serializer(profile)
            response_data = self.serializer.data
            self.make_response_success(data=response_data)
        except self.model_class.DoesNotExist:
            self.make_response_not_found()
        except Exception as e:
            self.resp = handler_exception_general(__name__, e)
        finally:
            return self.get_response()


class WhiteListedTokenApiView(CustomViewSetWithPagination):
    serializer_class = WhiteListedTokenSerializer
    permission_classes = (IsAuthenticated, IsVerified, IsSuperadmin)
    model_class = WhiteListedToken
    field_pk = 'whitelisted_id'
    http_method_names = ['GET', 'OPTIONS', 'HEAD']

    def get_queryset(self, *args, **kwargs):
        username = self.request.query_params.get('username', None)
        role_id = int(self.request.query_params.get('roleId', 0))

        order_by = self.request.query_params.get('orderBy', 'user')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')
        q = self.request.query_params.get('q', None)
        filters = dict()

        if role_id > 0:
            queryset = WhiteListedToken.objects.filter(user__profile__role=role_id)
        else:
            queryset = WhiteListedToken.objects.exclude(user__profile__role=Profile.OPERATOR)

        if username and len(username.strip()) > 0:
            filters['user__username__icontains'] = username

        if len(filters) > 0:
            queryset = queryset.filter(**filters).distinct()

        if q:
            queryset = queryset.filter(
                Q(user__profile__first_name__icontains=q) |
                Q(user__profile__last_name__icontains=q) |
                Q(user__profile__second_last_name__icontains=q) |
                Q(user__profile__email__icontains=q) |
                Q(user__profile__phone__icontains=q)
            ).distinct()

        order_by_filter = '{0}'.format("%s" % order_by if order_by_desc == 'false' else "-%s" % order_by)

        return queryset.order_by(order_by_filter)


class GroupApiView(CustomViewSet):
    serializer_class = GroupSerializer
    permission_classes = (IsAuthenticated, IsVerified)
    model_class = Group
    http_method_names = ['get', 'options', 'head', ]
    field_pk = 'group_id'
