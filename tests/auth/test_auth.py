from datetime import datetime, timedelta, UTC
import json
import uuid

import pytest
from httpx import Request, Response

from pyDataverse.auth import ApiTokenAuth, BearerTokenAuth, SignedURLAuth
from pyDataverse.exceptions import (
    ApiAuthorizationError,
    SignedUrlNotAvailableError,
    OperationFailedError,
)


class TestApiTokenAuth:
    def test_token_header_is_added_during_auth_flow(self):
        api_token = str(uuid.uuid4())
        auth = ApiTokenAuth(api_token)
        request = Request("GET", "https://example.org")
        assert "X-Dataverse-key" not in request.headers
        modified_request = next(auth.auth_flow(request))
        assert "X-Dataverse-key" in modified_request.headers
        assert modified_request.headers["X-Dataverse-key"] == api_token

    @pytest.mark.parametrize(
        "non_str_token", (123, object(), lambda x: x, 1.423, b"123", uuid.uuid4())
    )
    def test_raise_if_token_is_not_str(self, non_str_token):
        with pytest.raises(ApiAuthorizationError):
            ApiTokenAuth(non_str_token)


class TestBearerTokenAuth:
    def test_authorization_header_is_added_during_auth_flow(self):
        # Token as shown in RFC 6750
        bearer_token = "mF_9.B5f-4.1JqM"
        auth = BearerTokenAuth(bearer_token)
        request = Request("GET", "https://example.org")
        assert "Authorization" not in request.headers
        modified_request = next(auth.auth_flow(request))
        assert "Authorization" in modified_request.headers
        assert modified_request.headers["Authorization"] == f"Bearer {bearer_token}"

    @pytest.mark.parametrize(
        "non_str_token", (123, object(), lambda x: x, 1.423, b"123", uuid.uuid4())
    )
    def test_raise_if_token_is_not_str(self, non_str_token):
        with pytest.raises(ApiAuthorizationError):
            BearerTokenAuth(non_str_token)


class TestSignedURLs:
    def test_signed_url_with_api_token(self):
        auth = SignedURLAuth("testuser", ApiTokenAuth(str(uuid.uuid4())))
        request = Request("GET", "https://example.org/api/v1/example")
        assert "X-Dataverse-key" not in request.headers
        signing_request = next(auth.auth_flow(request))
        assert "X-Dataverse-key" in signing_request.headers
        assert signing_request.url == "https://example.org/api/admin/requestSignedUrl"

    def test_signed_url_with_bearer_token(self):
        auth = SignedURLAuth("testuser", BearerTokenAuth("mF_9.B5f-4.1JqM"))
        request = Request("GET", "https://example.org")
        assert "Authorization" not in request.headers
        signing_request = next(auth.auth_flow(request))
        assert "Authorization" in signing_request.headers
        assert signing_request.url == "https://example.org/api/admin/requestSignedUrl"

    @pytest.mark.parametrize(
        ["request_method", "username", "timeout"],
        [
            ("GET", "POST", "PUT"),
            [None, "testuser", "dataverseAdmin"],
            [None, 10, 5, 0, 100],
        ],
    )
    def test_signed_url_signing_request_payload(
        self, request_method: str, username: str | None, timeout: int | None
    ):
        auth = SignedURLAuth("testuser", ApiTokenAuth(str(uuid.uuid4())))
        url = "https://example.org/api/v1/example"
        request = Request("GET", url)
        auth_flow = auth.auth_flow(request)
        signing_request = next(auth_flow)
        assert signing_request.url == "https://example.org/api/admin/requestSignedUrl"
        assert "Content-Type" in signing_request.headers
        assert signing_request.headers["Content-Type"] == "application/json"
        payload = json.loads(signing_request.content.decode())
        assert payload["url"] == url
        assert payload["httpMethod"] == request_method
        if timeout is None:
            assert "timeOut" not in payload
        else:
            assert payload["timeOut"] == timeout
        if username is None:
            assert "username" not in payload
        else:
            assert payload["username"] == username

    @pytest.mark.parametrize("kwarg", ["data"])
    def test_signed_url_flow_tracks_data_payload(self, kwarg):
        auth = SignedURLAuth("testuser", ApiTokenAuth(str(uuid.uuid4())))
        url = "https://example.org/api/v1/example"
        payload = "data_payload"
        kwargs = {kwarg: payload}
        request = Request("GET", url, **kwargs)
        auth_flow = auth.auth_flow(request)
        signing_request: Request = next(auth_flow)
        assert payload not in signing_request.content.decode()
        signed_url = "https://example.org/api/v1/example?token=signed"
        response = {"status": "OK", "data": {"signedUrl": signed_url}}
        signing_response = Response(200, content=json.dumps(response))
        signed_request = auth_flow.send(signing_response)
        assert signed_request.url == signed_url
        assert payload in signing_request.content.decode()

    @pytest.mark.parametrize(
        ["request_method", "username", "timeout"],
        [
            ("GET", "POST", "PUT"),
            [None, "testuser", "dataverseAdmin"],
            [None, 10, 5, 0, 100],
        ],
    )
    def test_signed_url_flow_success(
        self, request_method: str, username: str | None, timeout: int | None
    ):
        auth = SignedURLAuth("testuser", ApiTokenAuth(str(uuid.uuid4())))
        url = "https://example.org/api/v1/example"
        request = Request("GET", url)
        auth_flow = auth.auth_flow(request)
        signing_request = next(auth_flow)
        assert signing_request.url == "https://example.org/api/admin/requestSignedUrl"

        until = (
            datetime.now(UTC)
            + timedelta(minutes=timeout if timeout is not None else 10)
        ).isoformat()[:-9]
        signed_token = "e574cb1689e1418f55f30b8fa6e6"  # actual tokens are longer
        signed_url = f"{url}&until={until}&user={username}&method={request_method}&token={signed_token}"
        response = {"status": "OK", "data": {"signedUrl": signed_url}}
        signing_response = Response(200, content=json.dumps(response))

        signed_request = auth_flow.send(signing_response)
        assert signed_request.url == signed_url
        assert signed_request.method == request_method

    def test_signed_url_flow_failure_not_available(self):
        api_token = str(uuid.uuid4())
        auth = SignedURLAuth("testuser", ApiTokenAuth(api_token))
        url = "https://example.org/api/v1/example"
        request = Request("GET", url)
        auth_flow = auth.auth_flow(request)
        signing_request = next(auth_flow)
        assert signing_request.url == "https://example.org/api/admin/requestSignedUrl"
        signing_response = Response(
            503,
            content=b'{status:"error", message:"Endpoint available from localhost only. Please contact the dataverse administrator"}',
        )
        with pytest.raises(SignedUrlNotAvailableError, ".*Endpoint.*localhost.*"):
            auth_flow.send(signing_response)

    def test_signed_url_flow_failure_server_error(self):
        api_token = str(uuid.uuid4())
        auth = SignedURLAuth("testuser", ApiTokenAuth(api_token))
        url = "https://example.org/api/v1/example"
        request = Request("GET", url)
        auth_flow = auth.auth_flow(request)
        signing_request = next(auth_flow)
        assert signing_request.url == "https://example.org/api/admin/requestSignedUrl"
        signing_response = Response(500, content=b"{}")

        with pytest.raises(OperationFailedError, ".*server.*error.*"):
            auth_flow.send(signing_response)
