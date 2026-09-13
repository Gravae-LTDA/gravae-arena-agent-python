"""Authenticated loopback completion notices; ACK only after durable enqueue."""
import hmac
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading


def start_completion_server(config, accept, state):
    settings = config['completionWebhook']
    token = settings['token']
    if not isinstance(token, str) or len(token) < 32:
        raise ValueError('COMPLETION_TOKEN_REQUIRED')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            status, body = 400, {'accepted': False}
            try:
                auth = self.headers.get('Authorization', '')
                if not hmac.compare_digest(auth, 'Bearer ' + token):
                    status = 401
                elif self.path != '/video-complete':
                    status = 404
                else:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 2048:
                        status = 413
                    else:
                        payload = json.loads(self.rfile.read(length))
                        if not isinstance(payload, dict):
                            raise ValueError('INVALID_NOTICE')
                        job_id = accept(payload)
                        status, body = 202, {'accepted': True, 'jobId': job_id}
                        state['lastNotificationError'] = None
                        state['notificationsAccepted'] = state.get('notificationsAccepted', 0) + 1
            except (ValueError, KeyError, TypeError):
                status = 400
            except Exception as error:
                status = 503
                state['lastNotificationError'] = type(error).__name__
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def setup(self):
            super().setup()
            self.connection.settimeout(15)
    server = HTTPServer(('127.0.0.1', int(settings.get('port', 8766))), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name='video-completion-webhook')
    thread.start()
    return server, thread
