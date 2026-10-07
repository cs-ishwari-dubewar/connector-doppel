"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from time import time
import requests

from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config
from .constants import DOPPEL_TOKEN_URL, DOPPEL_AUDIENCE, DOPPEL_GRANT_TYPE

logger = get_logger('doppel')

TOKEN_LIFETIME = 86400
TOKEN_REFRESH_BUFFER = 300


class DoppelAuth:

    def __init__(self, config):
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.verify_ssl = config.get('verify_ssl', True)

        if not self.client_id:
            raise ConnectorError('Client ID is required for OAuth authentication')

        if not self.client_secret:
            raise ConnectorError('Client Secret is required for OAuth authentication')

    def generate_token(self):
        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'audience': DOPPEL_AUDIENCE,
            'grant_type': DOPPEL_GRANT_TYPE
        }

        try:
            response = requests.post(
                DOPPEL_TOKEN_URL,
                json=payload,
                headers={'Content-Type': 'application/json'},
                verify=self.verify_ssl,
                timeout=60
            )

            if not response.ok:
                logger.error(
                    'OAuth authentication failed. Status code: %s, Response: %s',
                    response.status_code, response.text
                )
                raise ConnectorError(
                    'OAuth authentication failed: {0}:{1}'.format(response.status_code, response.text)
                )

            token_response = response.json()
            access_token = token_response.get('access_token')

            if not access_token:
                raise ConnectorError('Access token was not returned by the OAuth server')

            ts_now = time()
            expires_on = ts_now + TOKEN_LIFETIME - TOKEN_REFRESH_BUFFER

            return {
                'accessToken': access_token,
                'expiresOn': expires_on
            }

        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while connecting to the OAuth server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The OAuth server did not respond within the timeout period')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Unable to connect to the OAuth authentication server')
        except ConnectorError:
            raise
        except ValueError:
            raise ConnectorError('Invalid response received from the OAuth server')
        except Exception as err:
            logger.exception('OAuth authentication error')
            raise ConnectorError(str(err))

    def validate_token(self, connector_config, connector_info):
        ts_now = time()

        if not connector_config.get('accessToken'):
            logger.info('No existing Doppel token found. Generating a new token.')
            token_resp = self.generate_token()
            connector_config['accessToken'] = token_resp['accessToken']
            connector_config['expiresOn'] = token_resp['expiresOn']
            update_connnector_config(
                connector_info['connector_name'],
                connector_info['connector_version'],
                connector_config,
                connector_config['config_id']
            )
            return 'Bearer {0}'.format(connector_config['accessToken'])

        expires_on = connector_config.get('expiresOn')

        if ts_now > float(expires_on):
            logger.info('Doppel token expired at {0}. Generating a new token.'.format(expires_on))
            token_resp = self.generate_token()
            connector_config['accessToken'] = token_resp['accessToken']
            connector_config['expiresOn'] = token_resp['expiresOn']
            update_connnector_config(
                connector_info['connector_name'],
                connector_info['connector_version'],
                connector_config,
                connector_config['config_id']
            )
            return 'Bearer {0}'.format(connector_config['accessToken'])
        else:
            logger.info('Doppel token is valid till {0}'.format(expires_on))
            return 'Bearer {0}'.format(connector_config['accessToken'])


def check(config, connector_info):
    try:
        auth = DoppelAuth(config)

        if 'accessToken' not in config:
            token_resp = auth.generate_token()
            config['accessToken'] = token_resp['accessToken']
            config['expiresOn'] = token_resp['expiresOn']
            update_connnector_config(
                connector_info['connector_name'],
                connector_info['connector_version'],
                config,
                config['config_id']
            )
        else:
            auth.validate_token(config, connector_info)

        logger.info('Doppel OAuth authentication successful')
        return True

    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))