import threading

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