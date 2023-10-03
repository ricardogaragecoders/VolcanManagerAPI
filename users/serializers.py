from django.contrib.auth.models import User, Group
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from common.exceptions import CustomValidationError
from common.middleware import get_request
from common.serializers import StatusSerializer, CreatedAndUpdatedReadOnlyMixin
from .models import Profile, WhiteListedToken, ProfileVerification
from .utils import get_role_and_data
from .validators import _mobile_regex_validator, _password_regex_validator


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        from django.conf import settings
        if settings.ENABLE_2FACTOR_AUTHENTICATION and settings.ENABLE_SEND_EMAIL:
            return {'user': self.user}
        else:
            data = get_role_and_data(self.user, data)
        return data


class RegisterAdminSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100, required=True)
    last_name = serializers.CharField(max_length=100, required=True)
    second_last_name = serializers.CharField(max_length=100, required=False,
                                             default='', allow_blank=True, allow_null=True)
    email = serializers.EmailField(max_length=100, required=True)
    phone = serializers.CharField(max_length=10, validators=[_mobile_regex_validator], required=False,
                                  default='', allow_blank=True, allow_null=True)
    role = serializers.IntegerField(default=2, required=False)
    password = serializers.CharField(
        min_length=8,
        max_length=16,
        validators=[_password_regex_validator, ],
        error_messages={'password': _(u'Ingresa un password valido.'), },
        required=True
    )

    def validate(self, data):
        data = super(RegisterAdminSerializer, self).validate(data)
        email = data.get('email', None)
        role = int(data.get('role', Profile.SUPERADMIN))
        request = get_request()
        if email:
            if User.objects.filter(username=email).exists():
                raise CustomValidationError(detail=_(u'El correo electrónico ya estaba registrado'),
                                            code='email_exists')
        if role >= Profile.SUPERADMIN and not request.user.profile.isSuperadmin():
            raise CustomValidationError(detail=_(u'Solo personal de autorizado.'),
                                        code='no_permissions')

        if role > request.user.profile.role:
            raise CustomValidationError(
                detail=_(u'Solo puede registrar personas con el mismo rol que el suyo o menor'),
                code='no_permissions'
            )
        return data

    def create(self, validated_data):
        try:
            email = validated_data.get('email', '')
            password = validated_data.pop('password', 'Garage$21')
            second_last_name = validated_data.pop('second_last_name', '')
            phone = validated_data.pop('phone', '')
            role = validated_data.pop('role', 2)
            username = email
            if not User.objects.filter(username=username).exists():
                validated_data['username'] = username
                user = User.objects.create(**validated_data)
                group = Group.objects.get(pk=role)
                user.groups.add(group)
            else:
                user = User.objects.get(username=username)
            profile = user.profile
            profile.first_name = validated_data.get('first_name')
            profile.last_name = validated_data.get('last_name')
            profile.second_last_name = second_last_name
            profile.phone = phone
            profile.email = email
            profile.role = role
            profile.verification_email = True
            profile.save()
            user.set_password(password)
            user.save()
            return profile
        except Exception as e:
            print("Error at register users")
            print(validated_data)
            print(e.args.__str__())
            return None


class VerificationCodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=32, required=False)
    email = serializers.EmailField(max_length=100, required=False)
    token = serializers.CharField(max_length=256, required=False)

    def validate(self, data):
        data = super(VerificationCodeSerializer, self).validate(data)
        code = data.get('code', None)
        email = data.get('email', None)
        token = data.get('token', None)

        if token:
            try:
                import jwt
                from django.conf import settings
                data = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                code = data['code']
                email = data['email']
            except Exception as e:
                raise CustomValidationError(detail=_(u'El token no es valido.'),
                                            code='token_not_valid')
        else:
            if not code and not email:
                raise CustomValidationError(detail=_(u'El codigo y correo electronico son requeridos.'),
                                            code='code_email_required')
        now = timezone.localtime(timezone.now())

        try:
            verification = ProfileVerification.objects.get(code=code, data_verification=email)
        except ProfileVerification.DoesNotExist:
            raise CustomValidationError(detail=_(u'Código no existe.'), code='code_not_exists')

        if verification.validity_code:
            if verification.validity_code < now:
                raise CustomValidationError(detail=_(u'El tiempo se acabo.'), code='time_is_over')
        else:
            raise CustomValidationError(detail=_(u'El tiempo se acabo.'), code='time_is_over')

        data['verification'] = verification
        return data

    def create(self, validated_data):
        try:
            verification = validated_data.get('verification', None)
            if verification.type_verification in [ProfileVerification.VERIFICATION_EMAIL,
                                                  ProfileVerification.RECOVER_PASSWORD_EMAIL]:
                profile = verification.profile
                profile.verification_email = True
                if profile.has_changed:
                    profile.save()
            verification.is_verified = True
            verification.code = None
            verification.validity_code = None
            verification.save()
            return verification
        except Exception as e:
            print("Error at register users")
            print(validated_data)
            print(e.args.__str__())
            return None


class ResendCodeSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50, required=False, allow_blank=False, allow_null=True)
    email = serializers.EmailField(max_length=100, required=False, allow_blank=False, allow_null=True)
    code = serializers.CharField(max_length=50, required=False, allow_blank=False, allow_null=True)

    def validate(self, data):
        data = super(ResendCodeSerializer, self).validate(data)
        email = data.get('email', None)
        username = data.get('username', None)
        if email:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise CustomValidationError(detail=_('Usuario no encontrado.'),
                                            code='user_not_found')
        elif username:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                raise CustomValidationError(detail=_('Usuario no encontrado.'),
                                            code='user_not_found')
        else:
            raise CustomValidationError(detail=_('Los datos de email o username no fueron proporcionados.'),
                                        code='username_or_email_required')

        data['profile'] = user.profile
        return data

    def create(self, validated_data):
        code = validated_data.get('code', 'verification_2factor')
        try:
            profile = validated_data.get('profile', None)
            if code == 'verification_2factor':
                if profile.verification_email:
                    type_verification = ProfileVerification.VERIFICATION_2FACTOR
                else:
                    type_verification = ProfileVerification.VERIFICATION_EMAIL
            elif code == 'recover_password_email':
                type_verification = ProfileVerification.RECOVER_PASSWORD_EMAIL

            try:
                verification = ProfileVerification.objects.get(
                    profile=profile,
                    type_verification=type_verification,
                    data_verification=profile.user.email)
            except ProfileVerification.DoesNotExist:
                data = {
                    'profile': profile,
                    'type_verification': type_verification,
                    'data_verification': profile.user.email
                }
                verification = ProfileVerification.objects.create(**data)
            return verification
        except Exception as e:
            print("Error at register users")
            print(validated_data)
            print(e.args.__str__())
            return None


class RecoverPasswordSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50, required=False, default='')
    email = serializers.EmailField(max_length=100, required=False, default='')

    def validate(self, data):
        data = super(RecoverPasswordSerializer, self).validate(data)
        email = data.get('email', None)
        username = data.get('username', None)

        if username:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                raise CustomValidationError(
                    detail=_(u'El usuario no está registrado con este email.'),
                    code='useranme_not_exists')
        elif email:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise CustomValidationError(
                    detail=_(u'El usuario no está registrado con este email.'),
                    code='email_not_exists')

        if not user.is_active:
            raise CustomValidationError(
                detail=_(u'No se encontró una cuenta activa con las credenciales proporcionadas.'),
                code='no_active_account')

        # if email:
        #     if User.objects.filter(email=email).exclude(id__in=[user.id, ]).exists():
        #         raise CustomValidationError(
        #             detail=_(u'El correo electrónico está asociado con otro usuario.'),
        #             code='email_associated')

        data['profile'] = user.profile
        return data

    def create(self, validated_data):
        try:
            profile = validated_data.get('profile', None)
            try:
                verification = ProfileVerification.objects.get(profile=profile,
                                                               data_verification=profile.user.email,
                                                               type_verification=ProfileVerification.RECOVER_PASSWORD_EMAIL)
            except ProfileVerification.DoesNotExist:
                data = {
                    'profile': profile,
                    'type_verification': ProfileVerification.RECOVER_PASSWORD_EMAIL,
                    'data_verification': profile.user.email
                }
                verification = ProfileVerification.objects.create(**data)
            return verification
        except Exception as e:
            print("Error at changepassword users")
            print(validated_data)
            print(e.args.__str__())
            return None


class ChangePasswordSerializer(serializers.Serializer):
    token = serializers.CharField(min_length=10, required=False, allow_null=True, allow_blank=True)
    password = serializers.CharField(
        min_length=8,
        max_length=16,
        validators=[_password_regex_validator, ],
        error_messages={
            'password': _(u'Ingresa un password valido.'),
        },
        required=True
    )

    def validate(self, data):
        data = super(ChangePasswordSerializer, self).validate(data)
        token = data.get('token', None)
        now = timezone.localtime(timezone.now())
        user = get_request().user
        if not user.is_authenticated:
            if token:
                try:
                    import jwt
                    from django.conf import settings
                    data_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                except Exception as e:
                    raise CustomValidationError(detail=_(u'El token no es valido.'),
                                                code='token_not_valid')
                if 'code' in data_token:
                    code = data_token['code']
                else:
                    raise CustomValidationError(detail=_(u'El token no es valido.'),
                                                code='token_not_valid')
                if 'email' in data_token:
                    email = data_token['email']
                else:
                    raise CustomValidationError(detail=_(u'El token no es valido.'),
                                                code='token_not_valid')
            else:
                raise CustomValidationError(detail=_(u'El token no es valido.'),
                                            code='token_not_valid')

            try:
                user = User.objects.get(email=email)
                profile = user.profile
            except User.DoesNotExist:
                raise CustomValidationError(detail=_(u'Usuario no encontrado.'),
                                            code='user_not_found')

            if len(code) >= 6:
                try:
                    verification = ProfileVerification.objects.get(code=code, profile=profile)
                    data['verification'] = verification
                except ProfileVerification.DoesNotExist:
                    raise CustomValidationError(detail=_(u'El codigo no fue encontrado'),
                                                code='code_not_valid')
            else:
                raise CustomValidationError(detail=_(u'El código es incorrecto.'),
                                            code='code_incorrect')

            if not verification.profile.verification:
                raise CustomValidationError(detail=_(u'El usuario no esta verificado.'),
                                            code='user_not_verificated')

            if verification.validity_code:
                if now > verification.validity_code:
                    raise CustomValidationError(detail=_(u'El tiempo se acabo.'),
                                                code='time_is_over')
            else:
                raise CustomValidationError(detail=_(u'El tiempo se acabo.'),
                                            code='time_is_over')

            if verification.type_verification not in [ProfileVerification.RECOVER_PASSWORD_PHONE,
                                                      ProfileVerification.RECOVER_PASSWORD_EMAIL]:
                raise CustomValidationError(detail=_(u'El tipo de codigo no es de este proceso.'),
                                            code='code_type_invalid')

        else:
            data['user'] = user
        return data

    def create(self, validated_data):
        try:
            password = validated_data.get('password', '')
            verification = validated_data.get('verification', None)
            user = validated_data.get('user', None)
            profile = verification.profile if verification else user.profile
            if not user:
                user = profile.user
            user.set_password(password)
            user.save()
            if verification:
                verification.code = None
                verification.validity_code = None
                verification.save()
            profile.change_password = False
            if profile.has_changed:
                profile.save()

            return {'status': 1}
        except Exception as e:
            print("Error at changepassword users")
            print(validated_data)
            print(e.args.__str__())
            return None


class ResetPasswordSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100, required=True)
    password = serializers.CharField(min_length=4, max_length=16, required=True)

    def validate(self, data):
        data = super(ResetPasswordSerializer, self).validate(data)
        username = data.get('username', '')
        user = get_request().user

        if user.profile.role < Profile.ADMIN:
            raise CustomValidationError(
                detail=_(u'No tiene permisos suficientes para llevar a cabo esta acción.'),
                code='no_permissions')

        try:
            profile = Profile.objects.get(user__username=username)
        except Profile.DoesNotExist:
            profile = None

        if profile:
            if user.profile.role < profile.role:
                raise CustomValidationError(
                    detail=_(u'No tiene permisos suficientes para llevar a cabo esta acción.'),
                    code='no_permissions')
            if not profile.verification_email:
                raise CustomValidationError(
                    detail=_(u'El usuario para restablecer la contraseña no está verificado.'),
                    code='user_not_verified')
        else:
            raise CustomValidationError(detail=_('El usuario no existe.'),
                                        code='user_not_exists')

        return data

    def create(self, validated_data):
        try:
            password = validated_data.get('password', '')
            username = validated_data.get('username', '')
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                user = None
            if user:
                user.set_password(password)
                user.save()
                profile = user.profile
                profile.change_password = True
                profile.save()
                return {'status': 1}
            else:
                return {'status': -1}
        except Exception as e:
            print("Error at reset password")
            print(validated_data)
            print(e.args.__str__())
            return None


class ProfileSimpleSerializer(CreatedAndUpdatedReadOnlyMixin, serializers.ModelSerializer):
    username = serializers.CharField(source='user.username')
    email = serializers.EmailField(max_length=100)
    phone = serializers.CharField(max_length=10)

    class Meta:
        model = Profile
        fields = ('id', 'username', 'first_name', 'last_name', 'second_last_name', 'email', 'phone',
                  'verification_email', 'verification_phone', 'change_password', 'role')
        read_only_fields = fields


class ProfileVerySimpleSerializer(CreatedAndUpdatedReadOnlyMixin, serializers.ModelSerializer):
    username = serializers.CharField(source='user.username')

    class Meta:
        model = Profile
        fields = ('id', 'username', 'email', 'verification_email', 'verification_phone', 'change_password', 'role')
        read_only_fields = fields


class ProfileSerializer(CreatedAndUpdatedReadOnlyMixin, serializers.ModelSerializer):
    username = serializers.CharField(max_length=100, required=False, source='user.username')
    email = serializers.EmailField(max_length=100, required=False)
    phone = serializers.CharField(max_length=10, validators=[_mobile_regex_validator], required=False, default='')
    status = StatusSerializer(read_only=True)

    class Meta:
        model = Profile
        fields = ('id', 'username', 'first_name', 'last_name', 'second_last_name',
                  'email', 'phone', 'role', 'status',
                  'verification_email', 'verification_phone', 'change_password',
                  'created_at', 'updated_at')
        read_only_fields = ('created_at', 'updated_at', 'verification_email', 'verification_phone', 'change_password')


class WhiteListedTokenSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField(read_only=True)

    role = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = WhiteListedToken
        fields = ('id', 'user', 'username', 'role', 'created_at')

    def get_username(self, instance):
        return instance.user.username if instance.user else ''

    def get_role(self, instance):
        try:
            return instance.user.profile.role if instance.user and instance.user.profile else ''
        except Exception as e:
            return '1'


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('name',)
        read_only_fields = fields
