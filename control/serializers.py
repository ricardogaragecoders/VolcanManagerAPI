from decimal import Decimal, InvalidOperation, DecimalException

from rest_framework import serializers
from django.db import transaction
from common.exceptions import CustomValidationError
from common.utils import is_valid_uuid
from control.models import Company, Operator
from django.utils.translation import gettext_lazy as _

from users.models import RoleType, Profile
from users.validators import _password_regex_validator, _mobile_regex_validator
from volcanmanagerapi import settings
from django.contrib.auth.models import User, Group


def get_decimal_from_request_data(data, field):
    try:
        s_field = data.get(field, '')
        if isinstance(s_field, str):
            if len(s_field) > 0:
                s_field = Decimal(s_field)
            else:
                s_field = ""
        else:
            s_field = Decimal(s_field)
        return s_field
    except (InvalidOperation, DecimalException) as e:
        raise CustomValidationError(detail=f"{field}: error en conversion de valor a decimal",
                                    code='422')


class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = ('id', 'name', 'volcan_issuer_id', 'thales_issuer_id', 'is_active')

    def validate(self, data):
        data = super(CompanySerializer, self).validate(data)
        company_name = data.get('name', None)
        request = self.context['request']
        user = request.user

        if not self.instance:
            if Company.objects.filter(name=company_name).exists():
                raise CustomValidationError(detail={'name': _('Existe una empresa con el mismo nombre.')},
                                            code='company_exists')
        elif company_name and Company.objects.filter(name=company_name).exclude(id=self.instance.id).exists():
            raise CustomValidationError(detail={'name': _('Existe una empresa con el mismo nombre.')},
                                        code='company_exists')
        return data


class CompanySimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Company
        fields = ('id', 'name', 'volcan_issuer_id')
        read_only_fields = fields


class OperatorSerializer(serializers.ModelSerializer):
    # users
    username = serializers.CharField(max_length=150, required=False, write_only=True)
    password = serializers.CharField(
        min_length=8,
        max_length=45,
        validators=[_password_regex_validator],
        error_messages={
            'password': _(u'Por favor introduce una contraseña válida.'),
        },
        required=False,
        allow_null=True,
        write_only=True
    )
    # data additional
    profile_id = serializers.UUIDField(write_only=True, required=False, allow_null=True)
    # profile
    first_name = serializers.CharField(max_length=100, required=True, write_only=True)
    last_name = serializers.CharField(max_length=100, required=True, write_only=True)
    second_last_name = serializers.CharField(max_length=100, required=False, default='', write_only=True,
                                             allow_blank=True, allow_null=True)
    email = serializers.EmailField(max_length=100, required=False, write_only=True, default='',
                                   allow_blank=True)
    phone = serializers.CharField(max_length=10, validators=[_mobile_regex_validator,], required=False,
                                  write_only=True, allow_blank=True, allow_null=True, default='')
    role = serializers.IntegerField(write_only=True, allow_null=True, default=RoleType.OPERATOR)
    # data additional
    volcan_issuer_id = serializers.CharField(max_length=3, write_only=True, allow_null=True, allow_blank=True)

    class Meta:
        model = Operator
        fields = ('id', 'username', 'password', 'first_name', 'last_name', 'second_last_name',
                  'phone', 'email', 'role', 'profile_id',  'volcan_issuer_id', 'is_active',
                  'created_at', 'updated_at')
        # read_only_fields = ('active',)

    def validate(self, data):
        data = super(OperatorSerializer, self).validate(data)
        username = data.get('username', None)
        profile_id = data.pop('profile_id', None)
        volcan_issuer_id = data.pop('volcan_issuer_id', None)
        request = self.context['request']
        user = request.user
        profile = None
        company = None if not self.instance else self.instance.company

        if profile_id and is_valid_uuid(profile_id):
            profile = Profile.objects.filter(unique_id=profile_id).first()

        if volcan_issuer_id:
            company = Company.objects.filter(volcan_issuer_id=volcan_issuer_id).first()

        data['company'] = company

        if not self.instance:
            if not profile:
                password = data.get('password', settings.DEFAULT_PASSWORD)

                first_name = data.get('first_name', None)
                last_name = data.get('last_name', None)
                email = data.get('email', None)
                if not username and email:
                    username = email

                if not username or not password:
                    raise CustomValidationError(detail={'username': _(u'Username es requerido.')},
                                                code='username_required')
                if not first_name or not last_name:
                    raise CustomValidationError(detail={'first_name': _('Nombre y apellidos son requeridos.')},
                                                code='profile_required')
                if User.objects.filter(username=username).exists():
                    raise CustomValidationError(detail={'username': _(u'Hay un usuario con el mismo correo electrónico.')},
                                                code='username_exists')
            else:
                data['profile'] = profile
        elif username and User.objects.filter(username=username).exclude(id=self.instance.profile.user.id).exists():
            raise CustomValidationError(detail={'username': _(u'Hay un usuario con el mismo correo electrónico.')},
                                        code='username_exists')
        if self.instance:
            if self.instance.profile.role >= user.profile.role and self.instance.profile.id != user.profile.id:
                raise CustomValidationError(
                    detail={'username': _(u'No tiene permiso para actualizar un perfil que no sea el suyo.')},
                    code='no_permissions')
        return data

    def create(self, validated_data):
        profile = validated_data.pop('profile', None)

        company = validated_data.get('company', None)
        username = validated_data.pop('username', None)
        password = validated_data.pop('password', settings.DEFAULT_PASSWORD)
        role = validated_data.pop('role', RoleType.OPERATOR)
        group = Group.objects.get(id=role)
        first_name = validated_data.pop('first_name', '')
        last_name = validated_data.pop('last_name', '')
        second_last_name = validated_data.pop('second_last_name', '')
        phone = validated_data.pop('phone', '')
        email = validated_data.pop('email', '')

        if not profile:
            user = User.objects.create(username=username, first_name=first_name, last_name=last_name, email=email)
            user.set_password(password)
            user.groups.add(group)
            user.save()

            profile = user.profile
            profile.first_name = first_name
            profile.last_name = last_name
            profile.second_last_name = second_last_name
            profile.email = email
            profile.phone = phone
            profile.verification_email = True
            profile.role = role
            profile.save()

        validated_data['profile'] = profile
        validated_data['company'] = company
        validated_data['is_active'] = True

        with transaction.atomic():
            instance = super(OperatorSerializer, self).create(validated_data)

        return instance

    def update(self, instance, validated_data):
        username = validated_data.pop('username', instance.profile.user.username)
        password = validated_data.pop('password', None)
        profile = instance.profile

        first_name = validated_data.pop('first_name', profile.first_name)
        last_name = validated_data.pop('last_name', profile.last_name)
        second_last_name = validated_data.pop('second_last_name', profile.second_last_name)
        phone = validated_data.pop('phone', profile.phone)
        email = validated_data.pop('email', profile.email)
        role = validated_data.pop('role', profile.role)

        profile.first_name = first_name
        profile.last_name = last_name
        profile.second_last_name = second_last_name
        profile.email = email
        profile.phone = phone
        profile.role = role

        if profile.has_changed:
            profile.save()

        with transaction.atomic():
            instance = super(OperatorSerializer, self).update(instance, validated_data)

        if username and password:
            user = instance.profile.user
            if username:
                user.username = username
            if password:
                user.set_password(password)
            user.save()

        return instance

    def to_representation(self, instance):
        issuer = dict()

        if instance.company:
            issuer = {
                'id': str(instance.company.id),
                'name': instance.company.name,
                'volcan_issuer_id': instance.company.volcan_issuer_id
            }

        return {
            'id': str(instance.id),
            'username': instance.profile.user.username,
            'issuer': issuer,
            'profile': {
                'id': str(instance.profile.unique_id),
                'first_name': instance.profile.first_name,
                'last_name': instance.profile.last_name,
                'second_last_name': instance.profile.second_last_name,
                'email': instance.profile.email,
                'phone': instance.profile.phone,
                'role': instance.profile.role,
            },
            'is_active': instance.is_active
        }


class CreacionEnteSerializer(serializers.Serializer):
    CIF = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    PERSONERIA = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    TIPO_IDENTIFICACION = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    DOCUMENTO_IDENTIFICACION = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    PRIMER_NOMBRE = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    SEGUNDO_NOMBRE = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    PRIMER_APELLIDO = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    SEGUNDO_APELLIDO = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    APELLIDO_CASADA = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    FECHA_NACIMIENTO = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    SEXO = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    ESTADO_CIVIL = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    PROFESION = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    SEGURO_SOCIAL = serializers.CharField(max_length=25, required=False, default="", allow_blank=True)
    PAIS_NACIMIENTO = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    PAIS_RESIDENCIA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    NACIONALIDAD = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    CODIGO_PROVINCIA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    CODIGO_CANTON = serializers.CharField(max_length=5, required=False, default="", allow_blank=True)
    CODIGO_DISTRITO = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    DIRECCION_1 = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_2 = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    CODIGO_POSTAL = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    TELEFONO_CASA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    CELULAR = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    TELEFONO_OFICINA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    EMAIL_PERSONAL = serializers.EmailField(max_length=100, required=False, default="", allow_blank=True)
    EMAIL_OFICINA = serializers.EmailField(max_length=100, required=False, default="", allow_blank=True)
    LUGAR_TRABAJO = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    DIRECCION_1_TRABAJO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_2_TRABAJO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    PUESTO = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    INGRESO_MENSUAL = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    FECHA_INGRESO_TRABAJO = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    OFICINA_EXT = serializers.CharField(max_length=5, required=False, default="", allow_blank=True)
    NOMBRE_CONYUGUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    APELLIDO_CONYUGUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    CEDULA_CONYUGUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    NOMBRE_PADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    APELLIDO_PADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    NOMBRE_MADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    APELLIDO_MADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    TIPO_GESTION = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('CIF', 'PERSONERIA', 'TIPO_IDENTIFICACION', 'DOCUMENTO_IDENTIFICACION',
                  'PRIMER_NOMBRE', 'SEGUNDO_NOMBRE', 'PRIMER_APELLIDO', 'SEGUNDO_APELLIDO', 'APELLIDO_CASADA',
                  'FECHA_NACIMIENTO', 'SEXO', 'ESTADO_CIVIL', 'PROFESION', 'SEGURO_SOCIAL', 'PAIS_NACIMIENTO',
                  'PAIS_RESIDENCIA', 'NACIONALIDAD', 'CODIGO_PROVINCIA', 'CODIGO_CANTON', 'CODIGO_DISTRITO',
                  'DIRECCION_1', 'DIRECCION_2', 'CODIGO_POSTAL', 'TELEFONO_CASA', 'CELULAR', 'TELEFONO_OFICINA',
                  'EMAIL_PERSONAL', 'EMAIL_OFICINA', 'LUGAR_TRABAJO', 'DIRECCION_1_TRABAJO', 'DIRECCION_2_TRABAJO',
                  'PUESTO', 'INGRESO_MENSUAL', 'FECHA_INGRESO_TRABAJO', 'OFICINA_EXT', 'NOMBRE_CONYUGUE',
                  'APELLIDO_CONYUGUE', 'CEDULA_CONYUGUE', 'NOMBRE_PADRE', 'APELLIDO_PADRE', 'NOMBRE_MADRE',
                  'APELLIDO_MADRE', 'TIPO_GESTION', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(CreacionEnteSerializer, self).validate(data)
        email_personal = data.get('EMAIL_PERSONAL', "").strip()
        email_oficina = data.get('EMAIL_OFICINA', "").strip()
        emisor = data.get('EMISOR', '').strip()

        if len(email_personal) == 0 and len(email_oficina) == 0:
            raise CustomValidationError(detail=u'Email es requerido', code='400')

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class CreacionEnteSectorizacionSerializer(serializers.Serializer):
    CIF = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    PERSONERIA = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    TIPO_IDENTIFICACION = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    DOCUMENTO_IDENTIFICACION = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    PRIMER_NOMBRE = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    SEGUNDO_NOMBRE = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    PRIMER_APELLIDO = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    SEGUNDO_APELLIDO = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    APELLIDO_CASADA = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    FECHA_NACIMIENTO = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    SEXO = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    ESTADO_CIVIL = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    PROFESION = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    SEGURO_SOCIAL = serializers.CharField(max_length=25, required=False, default="", allow_blank=True)
    PAIS_NACIMIENTO = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    PAIS_RESIDENCIA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    NACIONALIDAD = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    CODIGO_PROVINCIA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    CODIGO_CANTON = serializers.CharField(max_length=5, required=False, default="", allow_blank=True)
    CODIGO_DISTRITO = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    DIRECCION_1 = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_2 = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_3 = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_4 = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_5 = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    CODIGO_POSTAL = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    TELEFONO_CASA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    CELULAR = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    TELEFONO_OFICINA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    EMAIL_PERSONAL = serializers.EmailField(max_length=100, required=False, default="", allow_blank=True)
    EMAIL_OFICINA = serializers.EmailField(max_length=100, required=False, default="", allow_blank=True)
    LUGAR_TRABAJO = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    CODIGO_PROVINCIA_TRABAJO = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    CODIGO_CANTON_TRABAJO = serializers.CharField(max_length=5, required=False, default="", allow_blank=True)
    CODIGO_DISTRITO_TRABAJO = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    DIRECCION_1_TRABAJO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_2_TRABAJO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_3_TRABAJO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_4_TRABAJO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_5_TRABAJO = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    PUESTO = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    INGRESO_MENSUAL = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    FECHA_INGRESO_TRABAJO = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    OFICINA_EXT = serializers.CharField(max_length=5, required=False, default="", allow_blank=True)
    NOMBRE_CONYUGUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    APELLIDO_CONYUGUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    CEDULA_CONYUGUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    NOMBRE_PADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    APELLIDO_PADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    NOMBRE_MADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    APELLIDO_MADRE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    TIPO_GESTION = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('CIF', 'PERSONERIA', 'TIPO_IDENTIFICACION', 'DOCUMENTO_IDENTIFICACION',
                  'PRIMER_NOMBRE', 'SEGUNDO_NOMBRE', 'PRIMER_APELLIDO', 'SEGUNDO_APELLIDO', 'APELLIDO_CASADA',
                  'FECHA_NACIMIENTO', 'SEXO', 'ESTADO_CIVIL', 'PROFESION', 'SEGURO_SOCIAL', 'PAIS_NACIMIENTO',
                  'PAIS_RESIDENCIA', 'NACIONALIDAD', 'CODIGO_PROVINCIA', 'CODIGO_CANTON', 'CODIGO_DISTRITO',
                  'DIRECCION_1', 'DIRECCION_2', 'DIRECCION_3', 'DIRECCION_4', 'DIRECCION_5', 'CODIGO_POSTAL',
                  'TELEFONO_CASA', 'CELULAR', 'TELEFONO_OFICINA', 'EMAIL_PERSONAL', 'EMAIL_OFICINA', 'LUGAR_TRABAJO',
                  'CODIGO_PROVINCIA_TRABAJO', 'CODIGO_CANTON_TRABAJO', 'CODIGO_DISTRITO_TRABAJO',
                  'DIRECCION_1_TRABAJO', 'DIRECCION_2_TRABAJO', 'DIRECCION_3_TRABAJO', 'DIRECCION_4_TRABAJO',
                  'DIRECCION_5_TRABAJO', 'PUESTO', 'INGRESO_MENSUAL', 'FECHA_INGRESO_TRABAJO', 'OFICINA_EXT',
                  'NOMBRE_CONYUGUE', 'APELLIDO_CONYUGUE', 'CEDULA_CONYUGUE', 'NOMBRE_PADRE', 'APELLIDO_PADRE',
                  'NOMBRE_MADRE', 'APELLIDO_MADRE', 'TIPO_GESTION', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(CreacionEnteSectorizacionSerializer, self).validate(data)
        email_personal = data.get('EMAIL_PERSONAL', "").strip()
        email_oficina = data.get('EMAIL_OFICINA', "").strip()
        emisor = data.get('EMISOR', '').strip()

        if len(email_personal) == 0 and len(email_oficina) == 0:
            raise CustomValidationError(detail=u'Email es requerido', code='400')

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class AltaCuentaTarjetaSerializer(serializers.Serializer):
    ID_ENTE_OWNER = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    NOMBRE_TARJETA = serializers.CharField(max_length=30, required=False, default="", allow_blank=True)
    TIPO_TARJETA = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    TARJETA_PREEXPEDIDA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    ID_ENTE_ADDITIONAL = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    TARJETA_VIRTUAL = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    PRODUCTO_BIN = serializers.CharField(max_length=9, required=False, default="", allow_blank=True)
    LIMITE_CRED_TITULAR = serializers.CharField(max_length=19, required=False, default="", allow_blank=True)
    LIMITE_CONSUMO_ADICIONAL = serializers.CharField(max_length=19, required=False, default="", allow_blank=True)
    CICLO_CORTE_TITULAR = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    PLAN_TITULAR = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    CODIGO_LEALTAD_TITULAR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    ENVIO_EDC_TITULAR = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    EMAIL_EDC_TITULAR = serializers.CharField(max_length=100, required=False, default="", allow_blank=True)
    DIRECCION_1_EDC_TITULAR = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    DIRECCION_2_EDC_TITULAR = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)
    CIUDAD_EDC_TITULAR = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    PROVINCIA_EDC_TITULAR = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    CODIGO_POSTAL_EDC_TITULAR = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    PAIS_EDC_TITULAR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    IBAN_INTERNACIONAL = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    IBAN_LOCAL = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    VENDEDORES_TC = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    INDICADOR_POLIZA = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('ID_ENTE_OWNER', 'NOMBRE_TARJETA', 'TIPO_TARJETA', 'TARJETA_PREEXPEDIDA',
                  'ID_ENTE_ADDITIONAL', 'TARJETA_VIRTUAL', 'PRODUCT_BIN', 'LIMITE_CRED_TITULAR',
                  'LIMITE_CONSUMO_ADICIONAL', 'CICLO_CORTE_TITULAR', 'PLAN_TITULAR', 'CODIGO_LEALTAD_TITULAR',
                  'ENVIO_EDC_TITULAR', 'EMAIL_EDC_TITULAR', 'DIRECCION_1_EDC_TITULAR', 'DIRECCION_2_EDC_TITULAR',
                  'CIUDAD_EDC_TITULAR', 'PROVINCIA_EDC_TITULAR', 'CODIGO_POSTAL_EDC_TITULAR', 'PAIS_EDC_TITULAR',
                  'IBAN_INTERNACIONAL', 'IBAN_LOCAL', 'VENDEDORES_TC', 'INDICADOR_POLIZA',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(AltaCuentaTarjetaSerializer, self).validate(data)
        card_name = data.get('NOMBRE_TARJETA', "").strip()
        type_card = data.get('TIPO_TARJETA', "").strip()
        card_virtual = data.get('TARJETA_VIRTUAL', "").strip()
        titular_shipment = data.get('ENVIO_EDC_TITULAR', "").strip()
        emisor = data.get('EMISOR', '').strip()

        data['NOMBRE_TARJETA'] = card_name
        data['TIPO_TARJETA'] = type_card
        data['TARJETA_VIRTUAL'] = card_virtual
        data['ENVIO_EDC_TITULAR'] = titular_shipment
        data['EMISOR'] = emisor

        if len(card_name) == 0:
            raise CustomValidationError(detail=u'Nombre de tarjeta es requerido', code='400')

        if len(type_card) == 0:
            raise CustomValidationError(detail=u'Tipo de tarjeta es requerido', code='400')

        # if len(card_virtual) == 0:
        #     raise CustomValidationError(detail=u'Valor tarjeta virtual es requerido', code='400')
        #
        # if len(titular_shipment) == 0:
        #     raise CustomValidationError(detail=u'Valor tarjeta virtual es requerido', code='400')

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')

        return data


class ConsultaCuentaSerializer(serializers.Serializer):
    CUENTA = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    CIF = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    ID_OWNER = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    TIPO_IDENTIFICACION = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    DOC_IDENTIFICACION = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    MONEDA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('CUENTA', 'CIF', 'ID_OWNER', 'TIPO_IDENTIFICACION', 'DOC_IDENTIFICACION',
                  'MONEDA', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaCuentaSerializer, self).validate(data)
        cuenta = data.get('CUENTA', "").strip()
        cif = data.get('CIF', "").strip()
        id_owner = data.get('ID_OWNER', "").strip()
        tipo_identificacion = data.get('TIPO_IDENTIFICACION', "").strip()
        doc_identificacion = data.get('DOC_IDENTIFICACION', "").strip()
        emisor = data.get('EMISOR', '').strip()

        data['CUENTA'] = cuenta
        data['CIF'] = cif
        data['ID_OWNER'] = id_owner
        data['TIPO_IDENTIFICACION'] = tipo_identificacion
        data['DOC_IDENTIFICACION'] = doc_identificacion

        if len(cuenta) == 0 and len(cif) == 0 and len(id_owner) == 0 and len(tipo_identificacion) == 0 and len(
                doc_identificacion) == 0:
            raise CustomValidationError(detail=u'No fue proporcionado ningun filtro para hacer la busqueda',
                                        code='400')
        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class ConsultaTarjetaSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    CIF = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    ID_OWNER = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    TIPO_IDENTIFICACION = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    DOC_IDENTIFICACION = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'CIF', 'ID_OWNER', 'TIPO_IDENTIFICACION', 'DOC_IDENTIFICACION',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaTarjetaSerializer, self).validate(data)
        tarjeta = data.get('TARJETA', "").strip()
        cif = data.get('CIF', "").strip()
        id_owner = data.get('ID_OWNER', "").strip()
        tipo_identificacion = data.get('TIPO_IDENTIFICACION', "").strip()
        doc_identificacion = data.get('DOC_IDENTIFICACION', "").strip()
        emisor = data.get('EMISOR', '').strip()

        data['TARJETA'] = tarjeta
        data['CIF'] = cif
        data['ID_OWNER'] = id_owner
        data['TIPO_IDENTIFICACION'] = tipo_identificacion
        data['DOC_IDENTIFICACION'] = doc_identificacion

        if len(tarjeta) == 0 and len(cif) == 0 and len(id_owner) == 0 and len(tipo_identificacion) == 0 and len(
                doc_identificacion) == 0:
            raise CustomValidationError(detail=u'No fue proporcionado ningun filtro para hacer la busqueda',
                                        code='400')
        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class CambioPINSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    PIN = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'PIN', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(CambioPINSerializer, self).validate(data)
        tarjeta = data.get('TARJETA', "").strip()
        pin = data.get('PIN', "").strip()
        emisor = data.get('EMISOR', '').strip()

        data['TARJETA'] = tarjeta
        data['PIN'] = pin

        if len(tarjeta) == 0:
            raise CustomValidationError(detail=u'El numbero de tarjeta es requerido',
                                        code='422')
        if len(pin) == 0:
            raise CustomValidationError(detail=u'El nuevo PIN es requerido',
                                        code='422')
        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class ExtrafinanciamientoSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    MONEDA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    IMPORTE = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    TASA = serializers.CharField(max_length=5, required=False, default="", allow_blank=True, allow_null=True)
    PLAZO = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    TIPO = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    COMERCIO = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    OFICINA = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'MONEDA', 'IMPORTE', 'TASA', 'PLAZO', 'REFERENCIA', 'TIPO',
                  'COMERCIO','OFICINA', 'EMISOR',  'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ExtrafinanciamientoSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        amount = get_decimal_from_request_data(data, 'IMPORTE')
        tax = get_decimal_from_request_data(data, 'TASA')
        emisor = data.get('EMISOR', '').strip().upper()

        if isinstance(amount, Decimal):
            amounts = ("%.2f" % amount).split('.')
            data['IMPORTE'] = amounts[0].zfill(17) + amounts[1].zfill(2)

        if isinstance(tax, Decimal):
            taxes = ("%.2f" % tax).split('.')
            data['TASA'] = taxes[0].zfill(2) + taxes[1].zfill(2)

        data['TARJETA'] = card

        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido',
                                        code='422')
        # if not importe.isnumeric():
        #     raise CustomValidationError(detail=u'El importe no es numerico',
        #                                 code='400')

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')

        data['EMISOR'] = emisor

        if emisor == "CMF":
            # data['OFICINA'] = "CMF00007"
            pass
        elif emisor == "FID":
            data['OFICINA'] = "0002"
        elif emisor == 'GMO':
            data['OFICINA'] = "GMG002"
        return data


class CambioLimitesSerializer(serializers.Serializer):
    CUENTA = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    LIMITE_CR = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    LIMITE_CON = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    LIMITE_EXTRA = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    MONEDA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('CUENTA', 'TARJETA', 'LIMITE_CR', 'LIMITE_CON', 'LIMITE_EXTRA', 'MONEDA', 'REFERENCIA',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(CambioLimitesSerializer, self).validate(data)
        account = data.get('CUENTA', "").strip()
        card = data.get('TARJETA', "").strip()
        limite_cr = get_decimal_from_request_data(data, 'LIMITE_CR')
        limite_con = get_decimal_from_request_data(data, 'LIMITE_CON')
        limite_extra = get_decimal_from_request_data(data, 'LIMITE_EXTRA')
        emisor = data.get('EMISOR', '').strip()

        if isinstance(limite_cr, Decimal):
            limits_cr = ("%.2f" % get_decimal_from_request_data(data, 'LIMITE_CR')).split('.')
            data['LIMITE_CR'] = limits_cr[0].zfill(17) + limits_cr[1].zfill(2)

        if isinstance(limite_con, Decimal):
            limits_con = ("%.2f" % get_decimal_from_request_data(data, 'LIMITE_CON')).split('.')
            data['LIMITE_CON'] = limits_con[0].zfill(17) + limits_con[1].zfill(2)

        if isinstance(limite_extra, Decimal):
            limits_extra = ("%.2f" % get_decimal_from_request_data(data, 'LIMITE_EXTRA')).split('.')
            data['LIMITE_EXTRA'] = limits_extra[0].zfill(17) + limits_extra[1].zfill(2)

        data['TARJETA'] = card
        data['CUENTA'] = account

        if len(card) == 0 and len(account) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta o cuenta es requerido',
                                        code='400')

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class CambioEstatusTDCSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    CUENTA = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    ESTATUS = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    MOTIVO = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'CUENTA', 'ESTATUS', 'MOTIVO', 'REFERENCIA',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(CambioEstatusTDCSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        account = data.get('CUENTA', "").strip()
        emisor = data.get('EMISOR', '').strip()

        data['TARJETA'] = card
        data['CUENTA'] = account
        if len(card) == 0 and len(account) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta o cuenta es requerido',
                                        code='400')
        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class ReposicionTarjetasSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    TIPO_USO = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    EMISION = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    TARJETA_ASIGNADA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    MOTIVO_REPO = serializers.CharField(max_length=30, required=False, default="", allow_blank=True)
    OFICINA_ENTREGA = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    NOMBRE_TARJETA = serializers.CharField(max_length=30, required=False, default="", allow_blank=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'TIPO_USO', 'EMISION', 'TARJETA_ASIGNADA', 'MOTIVO_REPO', 'OFICINA_ENTREGA',
                  'NOMBRE_TARJETA', 'REFERENCIA', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ReposicionTarjetasSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        # card_assigned = data.get('TARJETA_ASIGNADA', "").strip()
        emisor = data.get('EMISOR', '').strip()

        data['TARJETA'] = card
        # data['TARJETA_ASIGNADA'] = card_assigned
        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido',
                                        code='400')
        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class GestionTransaccionesSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=35, required=False, default="", allow_blank=True)
    TRANSACCION = serializers.CharField(max_length=6, required=False, default="", allow_blank=True)
    IMPORTE = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    MONEDA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    FECHA_TRX = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    HORA_TRX = serializers.CharField(max_length=6, required=False, default="", allow_blank=True)
    CVV2 = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    FECVENTO = serializers.CharField(max_length=4, required=False, default="", allow_blank=True)
    FINANCIABLE = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    CHEQUE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    PLAZA = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    NO_FINANCIAMIENTO = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    ORIGEN_MOV = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    DOC_OPER = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    AUTORIZACION = serializers.CharField(max_length=6, required=False, default="", allow_blank=True)
    COMERCIO = serializers.CharField(max_length=24, required=False, default="", allow_blank=True)
    CIUDAD = serializers.CharField(max_length=13, required=False, default="", allow_blank=True)
    PAIS = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    SUCURSAL = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'TRANSACCION', 'IMPORTE', 'MONEDA', 'FECHA_TRX', 'HORA_TRX', 'CVV2', 'FECVENTO',
                  'FINANCIABLE', 'CHEQUE', 'PLAZA', 'NO_FINANCIAMIENTO', 'REFERENCIA', 'ORIGEN_MOV', 'DOC_OPER',
                  'AUTORIZACION', 'COMERCIO', 'CIUDAD', 'PAIS', 'SUCURSAL', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(GestionTransaccionesSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        amount = get_decimal_from_request_data(data, 'IMPORTE')
        emisor = data.get('EMISOR', '').strip()

        if isinstance(amount, Decimal):
            amounts = ("%.2f" % amount).split('.')
            data['IMPORTE'] = amounts[0].zfill(17) + amounts[1].zfill(2)

        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido',
                                        code='400')
        # if not importe.isnumeric():
        #     raise CustomValidationError(detail=u'El importe no es numerico',
        #                                 code='400')

        data['TARJETA'] = card

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class ConsultaEnteSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    ID_ENTE = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    CIF_ENTE = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    TIPO_IDENTIFICACION = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    DOCUMENTO_IDENTIFICACION = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'ID_ENTE', 'CIF_ENTE', 'TIPO_IDENTIFICACION', 'DOCUMENTO_IDENTIFICACION',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaEnteSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        id_ente = data.get('ID_ENTE', "").strip()
        cif_ente = data.get('CIF_ENTE', "").strip()
        tipo_identificacion = data.get('TIPO_IDENTIFICACION', "").strip()
        doc_identificacion = data.get('DOCUMENTO_IDENTIFICACION', "").strip()
        emisor = data.get('EMISOR', '').strip()

        data['TARJETA'] = card
        data['ID_ENTE'] = id_ente
        data['CIF_ENTE'] = cif_ente
        data['TIPO_IDENTIFICACION'] = tipo_identificacion
        data['DOCUMENTO_IDENTIFICACION'] = doc_identificacion

        if len(card) == 0 and len(id_ente) == 0 and len(cif_ente) == 0 and len(tipo_identificacion) == 0 and len(
                doc_identificacion) == 0:
            raise CustomValidationError(detail=u'No fue proporcionado ningun filtro para hacer la busqueda',
                                        code='400')
        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class ConsultaMovimientosSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    FECHA_DE_CORTE = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    MOVIMIENTOS = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    CONSECUTIVO_EDO_CUENTA = serializers.CharField(max_length=4, required=False, default="", allow_blank=True)
    LLAVE_EDO_CUENTA = serializers.CharField(max_length=17, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'FECHA_DE_CORTE', 'MOVIMIENTOS', 'CONSECUTIVO_EDO_CUENTA', 'LLAVE_EDO_CUENTA',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaMovimientosSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        fecha_de_corte = data.get('FECHA_DE_CORTE', "").strip()
        emisor = data.get('EMISOR', '').strip()

        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido',
                                        code='400')
        data['TARJETA'] = card

        if len(fecha_de_corte) == 0:
            raise CustomValidationError(detail=u'La fecha de corte es requerido',
                                        code='400')
        data['FECHA_DE_CORTE'] = fecha_de_corte

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        data['EMISOR'] = emisor
        return data


class ConsultaPuntosSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaPuntosSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        emisor = data.get('EMISOR', '').strip()

        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido', code='400')
        data['TARJETA'] = card

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        data['EMISOR'] = emisor
        return data


class IntraExtrasSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    CODIGO_PLAN = serializers.CharField(max_length=5, required=False, default="", allow_blank=True)
    MONEDA = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    IMPORTE = serializers.CharField(max_length=19, required=False, default="", allow_blank=True, allow_null=True)
    PLAZO = serializers.CharField(max_length=2, required=False, default="", allow_blank=True, allow_null=True)
    REFERENCIA = serializers.CharField(max_length=12, required=False, default="", allow_blank=True)
    COMERCIO = serializers.CharField(max_length=40, required=False, default="", allow_blank=True)
    VENDEDOR = serializers.CharField(max_length=5, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'CODIGO_PLAN', 'MONEDA', 'IMPORTE', 'PLAZO', 'REFERENCIA', 'COMERCIO', 'VENDEDOR',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(IntraExtrasSerializer, self).validate(data)
        card = data.get('TARJETA', "").strip()
        plan_code = data.get('CODIGO_PLAN', "").strip()
        currency = data.get('MONEDA', "").strip()
        term = data.get('PLAZO', "").strip()
        commerce = data.get('COMERCIO', "").strip()
        amount = get_decimal_from_request_data(data, 'IMPORTE')
        emisor = data.get('EMISOR', '').strip()

        if isinstance(amount, Decimal):
            amounts = ("%.2f" % amount).split('.')
            data['IMPORTE'] = amounts[0].zfill(17) + amounts[1].zfill(2)

        if len(card) == 0:
            raise CustomValidationError(detail=u'El numero de tarjeta es requerido',
                                        code='400')
        data['TARJETA'] = card

        if len(plan_code) == 0:
            raise CustomValidationError(detail=u'El codigo de plan es requerido',
                                        code='400')
        data['CODIGO_PLAN'] = plan_code

        if len(currency) == 0:
            raise CustomValidationError(detail=u'La moneda es requerido',
                                        code='400')
        data['MONEDA'] = currency

        if len(term) == 0:
            raise CustomValidationError(detail=u'El plazo es requerido',
                                        code='400')
        data['PLAZO'] = term

        if len(commerce) == 0:
            raise CustomValidationError(detail=u'El comercio es requerido',
                                        code='400')
        data['COMERCIO'] = commerce

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class ConsultaIntraExtraF1Serializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=22, required=False, default="", allow_blank=True)
    CIF = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    ID_OWNER = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    TIPO_IDENTIFICACION = serializers.CharField(max_length=2, required=False, default="", allow_blank=True)
    DOC_IDENTIFICACION = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    DOC_FINAN = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    TIPO_FINAN = serializers.CharField(max_length=20, required=False, default="", allow_blank=True)
    PAGINA = serializers.CharField(max_length=100, required=False, default="", allow_blank=True)
    DIRECCION = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'CIF', 'ID_OWNER', 'TIPO_IDENTIFICACION', 'DOC_IDENTIFICACION',
                  'DOC_FINAN', 'TIPO_FINAN', 'PAGINA', 'DIRECCION',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaIntraExtraF1Serializer, self).validate(data)
        tarjeta = data.get('TARJETA', "").strip()
        cif = data.get('CIF', "").strip()
        id_owner = data.get('ID_OWNER', "").strip()
        tipo_identificacion = data.get('TIPO_IDENTIFICACION', "").strip()
        doc_identificacion = data.get('DOC_IDENTIFICACION', "").strip()
        emisor = data.get('EMISOR', '').upper().strip()

        data['TARJETA'] = tarjeta
        data['CIF'] = cif
        data['ID_OWNER'] = id_owner
        data['TIPO_IDENTIFICACION'] = tipo_identificacion
        data['DOC_IDENTIFICACION'] = doc_identificacion

        if len(tarjeta) == 0 and len(cif) == 0 and len(id_owner) == 0 and len(tipo_identificacion) == 0 and len(
                doc_identificacion) == 0:
            raise CustomValidationError(detail=u'No fue proporcionado ningun filtro para hacer la busqueda',
                                        code='400')
        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class ConsultaTransaccionesXFechaSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    FEC_INICIO = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    HOR_INICIO = serializers.CharField(max_length=6, required=False, default="", allow_blank=True)
    FEC_FINAL = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    HOR_FINAL = serializers.CharField(max_length=6, required=False, default="", allow_blank=True)
    TIPO_MOV = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    PAGINA = serializers.CharField(max_length=35, required=False, default="", allow_blank=True)
    DIRECCION = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'FEC_INICIO', 'HOR_INICIO', 'FEC_FINAL', 'HOR_FINAL', 'TIPO_MOV',
                  'PAGINA', 'DIRECCION', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaTransaccionesXFechaSerializer, self).validate(data)
        tarjeta = data.get('TARJETA', "").strip()
        fecha_inicio = data.get('FEC_INICIO', "").strip()
        fecha_final = data.get('FEC_FINAL', "").strip()
        hora_inicio = data.get('HOR_INICIO', "").strip()
        hora_final = data.get('HOR_FINAL', "").strip()
        emisor = data.get('EMISOR', '').upper().strip()

        data['TARJETA'] = tarjeta
        data['FEC_INICIO'] = fecha_inicio
        data['HOR_INICIO'] = hora_inicio
        data['FEC_FINAL'] = fecha_final
        data['HOR_FINAL'] = hora_final

        if len(tarjeta) == 0 and len(fecha_inicio) == 0 and len(fecha_final) == 0 and len(hora_inicio) == 0 and len(
                hora_final) == 0:
            raise CustomValidationError(detail=u'No fue proporcionado ningun filtro para hacer la busqueda',
                                        code='400')
        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class ConsultaCVV2Serializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaCVV2Serializer, self).validate(data)
        tarjeta = data.get('TARJETA', "").strip()
        emisor = data.get('EMISOR', '').upper().strip()

        data['TARJETA'] = tarjeta

        if len(tarjeta) == 0:
            raise CustomValidationError(detail=u'Tarjetqa es requerida', code='400')

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')

        data['TARJETA'] = tarjeta
        data['EMISOR'] = emisor

        return data


class ConsultaEstadoCuentaSerializer(serializers.Serializer):
    TARJETA = serializers.CharField(max_length=16, required=False, default="", allow_blank=True)
    FECHA_DE_CORTE = serializers.CharField(max_length=8, required=False, default="", allow_blank=True)
    MOVIMIENTOS = serializers.CharField(max_length=1, required=False, default="", allow_blank=True)
    CONSECUTIVO_EDO_CUENTA = serializers.CharField(max_length=4, required=False, default="", allow_blank=True)
    LLAVE_EDO_CUENTA = serializers.CharField(max_length=17, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('TARJETA', 'FECHA_DE_CORTE', 'MOVIMIENTOS', 'CONSECUTIVO_EDO_CUENTA', 'LLAVE_EDO_CUENTA',
                  'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaEstadoCuentaSerializer, self).validate(data)
        tarjeta = data.get('TARJETA', "").strip()
        emisor = data.get('EMISOR', '').upper().strip()

        data['TARJETA'] = tarjeta

        if len(tarjeta) == 0:
            raise CustomValidationError(detail=u'Tarjeta es requerida', code='400')

        if len(emisor) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data


class ConsultaCobranzaSerializer(serializers.Serializer):
    CUENTA = serializers.CharField(max_length=15, required=False, default="", allow_blank=True)
    EMISOR = serializers.CharField(max_length=3, required=False, default="", allow_blank=True)
    USUARIO_ATZ = serializers.CharField(max_length=10, required=False, default="", allow_blank=True)
    ACCESO_ATZ = serializers.CharField(max_length=50, required=False, default="", allow_blank=True)

    class Meta:
        fields = ('CUENTA', 'EMISOR', 'USUARIO_ATZ', 'ACCESO_ATZ')

    def validate(self, data):
        data = super(ConsultaCobranzaSerializer, self).validate(data)
        account = data.get('CUENTA', "").strip()
        issuer = data.get('EMISOR', '').upper().strip()

        data['CUENTA'] = account

        if len(account) == 0:
            raise CustomValidationError(detail=u'Cuenta es requerida', code='400')

        if len(issuer) == 0:
            raise CustomValidationError(detail=u'Emisor es requerido', code='400')
        return data
