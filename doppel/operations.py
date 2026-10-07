"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import requests
from connectors.core.connector import get_logger, ConnectorError
from .constants import *
from connectors.core.utils import update_connnector_config
from .api_auth import DoppelAuth

logger = get_logger('doppel')


class Doppel(object):

    def __init__(self, config):
        base_url = config.get('server_url', '').strip('/')
        if not base_url.startswith('https://') and not base_url.startswith('http://'):
            base_url = 'https://{0}'.format(base_url)

        self.auth_type = config.get('auth_type', AUTH_TYPE_OAUTH)
        self.verify_ssl = config.get('verify_ssl', True)

        if self.auth_type == AUTH_TYPE_API_KEY:
            self.url = '{0}/{1}'.format(base_url, API_VERSION_V1)
        else:
            self.url = '{0}/{1}'.format(base_url, API_VERSION_V2)

    def _build_headers(self, config, connector_info):
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }

        if self.auth_type == AUTH_TYPE_API_KEY:
            api_key = config.get('api_key')
            user_api_key = config.get('user_api_key')

            if not api_key:
                raise ConnectorError('API Key is required for API Key authentication')

            headers['x-api-key'] = api_key
            if user_api_key:
                headers['x-user-api-key'] = user_api_key

        else:
            auth = DoppelAuth(config)
            token = auth.validate_token(config, connector_info)
            headers['Authorization'] = token

        return headers

    def make_api_call(self, endpoint, config, connector_info, method='POST', payload=None, params=None):
        service_endpoint = self.url + endpoint
        try:
            headers = self._build_headers(config, connector_info)
            response = requests.request(method, service_endpoint, json=payload,
                                         headers=headers, params=params,
                                         verify=self.verify_ssl, timeout=60)

            # Token refresh retry only applies to OAuth mode.
            if response.status_code == 401 and self.auth_type == AUTH_TYPE_OAUTH:
                logger.info('Received 401 Unauthorized. Generating a new Doppel OAuth token.')
                auth = DoppelAuth(config)
                token_response = auth.generate_token()
                config['accessToken'] = token_response['accessToken']
                config['expiresOn'] = token_response['expiresOn']
                update_connnector_config(
                    connector_info['connector_name'],
                    connector_info['connector_version'],
                    config,
                    config['config_id']
                )
                headers['Authorization'] = 'Bearer {0}'.format(token_response['accessToken'])
                response = requests.request(method, service_endpoint, json=payload,
                                             headers=headers, params=params,
                                             verify=self.verify_ssl)

            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(service_endpoint))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            else:
                logger.error("{0}".format(response.status_code))
                raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value != '' and value is not None:
            updated_payload[key] = value
    return updated_payload


def convert_datetime_to_api_format(date_time):
    date_time = date_time.split(".")[0]
    return date_time


def get_all_alerts(config, params, connector_info):
    dp = Doppel(config)
    endpoint = "alerts"
    query_parameters = {
        "search_key": params.get('search_key'),
        "queue_state": ALERT_STATE.get(params.get('queue_state')) if params.get('queue_state') else '',
        "product": PRODUCT.get(params.get('product')) if params.get('product') else '',
        "created_before": convert_datetime_to_api_format(params.get('created_before')) if params.get(
            'created_before') else '',
        "created_after": convert_datetime_to_api_format(params.get('created_after')) if params.get(
            'created_after') else '',
        "last_activity_timestamp": convert_datetime_to_api_format(params.get('last_activity_timestamp')) if params.get(
            'last_activity_timestamp') else '',
        "sort_type": SORT_BY.get(params.get('sort_type')) if params.get('sort_type') else '',
        "sort_order": SORT_ORDER.get(params.get('sort_order')) if params.get('sort_order') else '',
        "page": params.get('page'),
        "tags": params.get('tags')
    }
    query_parameters = check_payload(query_parameters)
    resp = dp.make_api_call(endpoint, config, connector_info, method='GET', params=query_parameters)
    return resp


def get_alert_details(config, params, connector_info):
    dp = Doppel(config)
    endpoint = "alert"
    query_parameters = {
        "id": params.get('id'),
        "entity": params.get('entity')
    }
    query_parameters = check_payload(query_parameters)
    resp = dp.make_api_call(endpoint, config, connector_info, method='GET', params=query_parameters)
    return resp


def update_alert(config, params, connector_info):
    dp = Doppel(config)
    endpoint = "alert"
    query_parameters = {
        "id": params.get('id'),
        "entity": params.get('entity')
    }
    query_parameters = check_payload(query_parameters)
    payload = {
        "queue_state": ALERT_STATE.get(params.get('queue_state')) if params.get('queue_state') else '',
        "entity_state": params.get('entity_state').lower() if params.get('entity_state') else '',
        "comment": params.get('comment'),
        "tag_action": params.get('tag_action').lower() if params.get('tag_action') else '',
        "tag_name": params.get('tag_name')
    }
    payload = check_payload(payload)
    resp = dp.make_api_call(endpoint, config, connector_info, method='PUT', params=query_parameters, payload=payload)
    return resp


def execute_an_api_call(config, params, connector_info):
    try:
        dp = Doppel(config)
        endpoint = params.get("endpoint")
        http_method = params.get("method")
        query_params = params.get("query_params") if params.get("query_params") else {}
        payload = params.get("payload") if params.get("payload") else {}
        if http_method in ("GET", "DELETE"):
            resp = dp.make_api_call(endpoint, config, connector_info, method=http_method, params=query_params)
        elif http_method == "POST":
            resp = dp.make_api_call(endpoint, config, connector_info, method=http_method, payload=payload)
        elif http_method == ("PUT", "PATCH"):
            resp = dp.make_api_call(endpoint, config, connector_info, method=http_method, params=query_params, payload=payload)
        else:
            raise ConnectorError(f"Unsupported HTTP method: {http_method}")
        return resp
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config, connector_info):
    try:
        resp = get_all_alerts(config, params={}, connector_info=connector_info)
        if resp:
            return True
    except Exception as err:
        logger.info(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_all_alerts': get_all_alerts,
    'get_alert_details': get_alert_details,
    'update_alert': update_alert,
    'execute_an_api_call': execute_an_api_call
}
