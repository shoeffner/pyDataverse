import uuid

import pytest
from httpx import Request

from pyDataverse.authentication import ApiTokenAuth, OAuthBearerTokenAuth
from pyDataverse.exceptions import ApiAuthorizationError


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
