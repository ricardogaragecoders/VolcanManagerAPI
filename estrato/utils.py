import requests

from estrato.models import EstratoApiKey


def call_volcan_manager_api(url_path, headers, method='POST', data=None, cert=None):
    status_code = 200
    response_data = {}
    print(f"Request {method}: {url_path}")
    print(f"Headers: {headers}")
    print(f"Request json: {data}")
    try:
        # Make the API request using the provided headers and data
        if method == 'GET':
            response = requests.get(
                url_path, headers=headers, params=data, cert=cert
            )
        else:   
            response = requests.request(
                method, url_path, headers=headers, data=data, cert=cert
            )
        status_code = response.status_code
        # logger moved up before response.raise_for_status

        if 'Content-Type' in response.headers:
            if 'application/json' in response.headers['Content-Type']:
                response_data = response.json() if status_code != 204 else {}
            else:
                response_data = response.content
        return response_data, status_code
    except requests.exceptions.Timeout:
        response_data, status_code = {'error': 'Error de conexion con servidor (Timeout)'}, 408
    except requests.exceptions.TooManyRedirects:
        response_data, status_code = {'error': 'Error de conexion con servidor (TooManyRedirects)'}, 429
    except requests.exceptions.RequestException as e:
        print(e.args.__str__())
        response_data, status_code = {'error': 'Error de conexion con servidor (RequestException)'}, 400
    except Exception as e:
        response_data, status_code = {'error': e.args.__str__()}, 500
    finally:
        print(f"Response {str(status_code)}: {response_data}")
        return response_data, status_code


def get_estrato_api_key_credentials(issuer_id):
    from django.core.cache import cache
    key_cache = f"estrato-api-key-{issuer_id}"
    if key_cache not in cache:
        register = EstratoApiKey.objects.filter(volcan_issuer_id=issuer_id).first()
        cache.set(key_cache, register, 60 * 60 * 24)
    return cache.get(key_cache)
