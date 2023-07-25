from django.utils.translation import gettext_lazy as _
from rest_framework import status, serializers
from rest_framework.exceptions import _get_error_details

from common.middleware import get_request


class CustomValidationError(serializers.ValidationError):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _('Invalid input.')
    default_code = 'invalid'

    def __init__(self, detail=None, code=None):
        if detail is None:
            detail = self.default_detail
        if code is None:
            code = self.default_code
        # For validation failures, we may collect many errors together,
        # so the details should always be coerced to a list if not already.
        if not isinstance(detail, dict) and not isinstance(detail, list):
            detail = [detail]
        request = get_request()
        if request and request.session:
            request.session['code'] = code

        self.detail = _get_error_details(detail, code)
