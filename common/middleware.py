import json
import pytz
import threading
import logging
from urllib.parse import parse_qs

from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

from common.models import MonitorCollection

logger = logging.getLogger('common.middleware.RequestLoggingMiddleware')
request_local = threading.local()


def get_request():
    return getattr(request_local, 'request', None)


def set_request(request):
    return setattr(request_local, 'request', request)


class RequestMiddleware():
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_local.request = request
        return self.get_response(request)

    def process_exception(self, request, exception):
        request_local.request = None

    def process_template_response(self, request, response):
        request_local.request = None
        return response


class RemoveServerHeaderMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        response = self.get_response(request)
        response['Server'] = "None of your beeswax!"
        return response


class RequestLoggingMiddleware(MiddlewareMixin):
    skip_logging_keywords = [
        "volcan/api/issuers", "volcan/api/operators", "volcan/api/Webhooks", "volcan/api/Notificaciones",
        "volcan/api/Transacciones", "thales/api/bin/configurations", "volcan/api/ApiKeys",
        "volcan/api/commons/monitor/systems", "volcan/api/reports", "volcan/api/currencies",
        "media/report", "media/account-statements", "static/swagger-ui",
        "favicon.ico"
    ]

    def process_request(self, request):
        if any(keyword in request.path for keyword in self.skip_logging_keywords):
            return

        # Save the raw body for later use
        request._body = request.body
        # Record the start time
        request.start_time = timezone.now()

    def process_response(self, request, response):
        if any(keyword in request.path for keyword in self.skip_logging_keywords):
            return response

        # Get the user, URL, request data, and response data
        user = request.user if request.user.is_authenticated else None
        if user:
            from control.models import Operator
            operator = Operator.objects.filter(profile__user_id=user.id).values('company__volcan_issuer_id').first()
            user_data = {
                "user_id": user.id,
                "username": user.username,
                "emisor": operator['company__volcan_issuer_id'] if operator else ''
            }
        else:
            user_data = {
                "user_id": 0,
                "username": "Anonymous"
            }
        method = request.method  # Get the HTTP method (GET, POST, PATCH, etc.)
        url = request.build_absolute_uri()

        # Extract and format headers
        relevant_headers = ["X-Correlation-Id", "Content-Type", "Host", "Accept",
                            "Accept-Language", "Accept-Encoding", "Origin", "Authorization"]
        headers = {key: (value if key.lower() != 'authorization' else 'Bearer ***') for key, value in
                   request.headers.items() if key in relevant_headers}
        if "Content-Type" in headers and headers["Content-Type"] == "application/x-www-form-urlencoded":
            # Convert URL-encoded form data to a dictionary
            request_data = parse_qs(request._body.decode('utf-8'))
            # Convert the dictionary to JSON
            request_data = {k: v[0] for k, v in request_data.items()}
        else:
            # Try to parse request data as JSON
            try:
                request_data = json.loads(request._body.decode('utf-8'))
            except (ValueError, TypeError):
                request_data = request._body.decode('utf-8')  # Keep as is if not JSON

        # Ofuscación de 'password' en request_data
        if isinstance(request_data, dict):
            if 'password' in request_data and 'username' in request_data:
                from control.models import Operator
                operator = Operator.objects.filter(profile__user__username=request_data['username']).values('company__volcan_issuer_id').first()
                user_data["emisor"] = operator['company__volcan_issuer_id'] if operator else ''
            if 'password' in request_data:
                request_data['password'] = '***'

        # Try to parse response data as JSON
        try:
            response_data = json.loads(response.content.decode('utf-8'))
        except (ValueError, TypeError):
            response_data = response.content.decode('utf-8')  # Keep as is if not JSON

        # Ofuscación de 'access_token' y 'refresh_token' en response_data
        if isinstance(response_data, dict):
            if 'access' in response_data:
                response_data['access'] = '***'
            if 'refresh' in response_data:
                response_data['refresh'] = '***'
            if 'access_token' in response_data:
                response_data['access_token'] = '***'
            if 'refresh_token' in response_data:
                response_data['refresh_token'] = '***'

            for k, v in response_data.items():
                if isinstance(v, list):
                    response_data[k] = len(v)

        # Calculate the time taken to process the request
        if hasattr(request, 'start_time'):
            time_taken = "{:.4f}".format(((timezone.now() - request.start_time).total_seconds()/1))
        else:
            time_taken = 'N/A'

        # Convert the current time to 'America/Mexico_City' timezone
        current_time = timezone.localtime(timezone.now(), pytz.timezone('America/Mexico_City'))

        # Get the response status code
        status_code = response.status_code

        # Prepare log entry in JSON format
        log_entry = {
            'created_at': current_time,  # Add the current date and time in 'America/Mexico_City' timezone
            'user': user_data,
            'method': method,
            'url': url,
            'headers': headers,
            'request_data': request_data,
            'response_data': response_data,
            'status_code': status_code,  # Include response status code
            'time_seconds': time_taken
        }

        if 'api-doc' not in url:
            db = MonitorCollection()
            db.insert_one(log_entry.copy())

            if ('rsp_success' in response_data and response_data['rsp_success'] is False) or (status_code not in [200, 201, 204]):
                # Log the JSON entry
                log_entry['created_at'] = log_entry['created_at'].isoformat()
                logger.info(json.dumps(log_entry, indent=4))

        return response
