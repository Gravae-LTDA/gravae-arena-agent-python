import io
import unittest
from unittest.mock import Mock
from contextlib import redirect_stdout

from device_gateway_client import GatewayConnection, operational_log


class ReconnectionTests(unittest.TestCase):
    def setUp(self):
        self.first = Mock(connected=False)
        self.second = Mock(connected=False)
        self.factory = Mock(side_effect=[self.first, self.second])
        self.register = Mock()
        self.connection = GatewayConnection({"deviceId": "device", "arenaId": "arena",
                                             "gatewayUrl": "wss://gateway", "deviceToken": "secret"},
                                            self.factory, self.register)

    def test_partial_connection_value_error_is_closed_and_next_attempt_is_fresh(self):
        self.first.connect.side_effect = ValueError('Client is not in a disconnected state')
        with self.assertRaises(ValueError):
            self.connection.connect()
        self.assertIsNone(self.connection.client)
        self.first.disconnect.assert_called_once()
        self.first.eio.disconnect.assert_called_once_with(abort=True)
        self.connection.connect()
        self.assertIs(self.connection.client, self.second)
        self.assertEqual(self.register.call_count, 2)
        for call in self.factory.call_args_list:
            self.assertFalse(call.kwargs['reconnection'])

    def test_namespace_disconnect_replaces_transport_before_reconnect(self):
        self.connection.connect()
        self.first.connected = False
        self.connection.connect()
        self.first.disconnect.assert_called_once()
        self.first.connect.assert_called_once()
        self.second.connect.assert_called_once()

    def test_disconnect_error_still_aborts_engineio(self):
        self.connection.connect()
        self.first.disconnect.side_effect = ValueError('secret transport details')
        with redirect_stdout(io.StringIO()) as output:
            self.connection.close()
        self.assertIsNone(self.connection.client)
        self.first.eio.disconnect.assert_called_once_with(abort=True)
        self.assertNotIn('secret transport details', output.getvalue())

    def test_logs_omit_credentials_and_arbitrary_nested_payload(self):
        with redirect_stdout(io.StringIO()) as output:
            operational_log('command.received', commandId='id', streamKey='secret',
                            rtmpUrl='rtmp://secret', streamId={'token': 'secret'})
        self.assertNotIn('secret', output.getvalue())
        self.assertIn('id', output.getvalue())


if __name__ == '__main__':
    unittest.main()
