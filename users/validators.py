from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _

_mobile_regex_validator = RegexValidator(
    regex=r"^\d{10}$",
    message=_(u'El número de teléfono debe tener 10 dígitos sin + o espacios.')
)

_code_regex_validator = RegexValidator(
    regex=r"^\d{6}$",
    message=_('El número de código debe tener 6 dígitos')
)

_password_regex_validator = RegexValidator(
    regex=r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])([A-Za-z\d$@$!%*?&]|[^ ]){8,45}$',
    message=_(u'Ingresa un password valido.')
)
