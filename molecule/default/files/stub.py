#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Slavi Pantaleev
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Stands in for the two parties OAuth2-Proxy talks to, so that the Molecule
# scenario can exercise it without an actual identity provider or application:
#
# - an OpenID Connect provider on OIDC_PORT, serving just enough discovery
#   metadata for OAuth2-Proxy to accept it. OAuth2-Proxy performs OIDC
#   discovery while starting up and exits when it cannot, so without this the
#   container never comes up at all and nothing else could be probed.
#
# - the protected upstream on UPSTREAM_PORT, echoing a marker string and the
#   requested path back. That marker is what tells a response which travelled
#   through OAuth2-Proxy to the upstream apart from one that OAuth2-Proxy
#   answered by itself.
#
# Both parts run in one throwaway container, on the container network that the
# role creates: Docker 28 and newer block containers on a bridge network from
# reaching ports published on that bridge's gateway, so a listener on the test
# host would not be reachable from the OAuth2-Proxy container.
#
# Deliberately not a working provider. Completing a sign-in would mean issuing
# an ID token signed with a key OAuth2-Proxy can verify through JWKS, and the
# standard library has no RSA. Everything up to the redirect to the
# authorization endpoint is real, and nothing beyond it is served at all.

import http.server
import json
import os
import socketserver
import threading

ISSUER = os.environ["ISSUER"]
OIDC_PORT = int(os.environ["OIDC_PORT"])
UPSTREAM_PORT = int(os.environ["UPSTREAM_PORT"])
UPSTREAM_MARKER = os.environ["UPSTREAM_MARKER"]

# Only the fields OAuth2-Proxy reads while starting up. It insists that
# `issuer` matches the URL it was configured with, which is what makes the
# redirect that `verify.yml` asserts on prove that the role's
# `oauth2_proxy_environment_variable_oidc_issuer_url` reached the process.
DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": ISSUER + "/authorize",
    "token_endpoint": ISSUER + "/token",
    "jwks_uri": ISSUER + "/jwks",
    "userinfo_endpoint": ISSUER + "/userinfo",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "email", "profile"],
}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def respond(self, status, content_type, body):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        print("%s %s" % (self.server.server_address[1], fmt % args), flush=True)


class OidcHandler(Handler):
    def do_GET(self):  # noqa: N802 - name mandated by http.server
        if self.path.startswith("/.well-known/openid-configuration"):
            self.respond(200, "application/json", json.dumps(DISCOVERY))
        elif self.path.startswith("/jwks"):
            # Never actually used: no ID token is ever issued to verify.
            self.respond(200, "application/json", json.dumps({"keys": []}))
        else:
            self.respond(404, "text/plain", "not found\n")


class UpstreamHandler(Handler):
    def do_GET(self):  # noqa: N802 - name mandated by http.server
        self.respond(200, "text/plain", "%s %s" % (UPSTREAM_MARKER, self.path))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


servers = [
    Server(("0.0.0.0", OIDC_PORT), OidcHandler),
    Server(("0.0.0.0", UPSTREAM_PORT), UpstreamHandler),
]

for server in servers[1:]:
    threading.Thread(target=server.serve_forever, daemon=True).start()

servers[0].serve_forever()
