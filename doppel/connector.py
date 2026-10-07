"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from .operations import operations, _check_health
from connectors.core.connector import Connector, get_logger, ConnectorError

logger = get_logger('doppel')


class Doppel(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            connector_info = {
                "connector_name": self._info_json.get('name'),
                "connector_version": self._info_json.get('version')
            }
            logger.info('execute [{}]'.format(operation))
            action = operations.get(operation)
            return action(config, params, connector_info)
        except Exception as err:
            logger.exception("An exception occurred [{}]".format(err))
            raise ConnectorError("An exception occurred [{}]".format(err))

    def check_health(self, config):
        logger.info('starting health check')
        connector_info = {
            "connector_name": self._info_json.get('name'),
            "connector_version": self._info_json.get('version')
        }
        _check_health(config, connector_info)
        logger.info('completed health check no errors')
