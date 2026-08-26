"""
Tests for authentication routes, specifically verifying that the
reset-password endpoint enforces authentication (CWE-306 fix).

Each test uses the pytest fixtures defined in conftest.py:
  - client   : Flask test client
  - sample_user / auth_headers : a non-admin user plus its Bearer token
  - admin_user / admin_auth_headers : an admin user plus its Bearer token
"""
import pytest
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_payload(email, new_password):
    return json.dumps({'email': email, 'new_password': new_password})


CONTENT_JSON = {'Content-Type': 'application/json'}


# ---------------------------------------------------------------------------
# reset-password: authentication gate
# ---------------------------------------------------------------------------

class TestResetPasswordRequiresAuth:
    """CWE-306 regression suite: unauthenticated callers MUST be rejected."""

    def test_no_token_returns_401(self, client, sample_user):
        """Without any Authorization header the endpoint must return 401."""
        response = client.post(
            '/api/auth/reset-password',
            data=_reset_payload(sample_user.email, 'NewPassword1!'),
            headers=CONTENT_JSON,
        )
        assert response.status_code == 401, (
            'reset-password must require authentication; got %d instead of 401'
            % response.status_code
        )

    def test_invalid_token_returns_401(self, client, sample_user):
        """A forged / garbage JWT must be rejected with 401."""
        response = client.post(
            '/api/auth/reset-password',
            data=_reset_payload(sample_user.email, 'NewPassword1!'),
            headers={**CONTENT_JSON, 'Authorization': 'Bearer this.is.not.a.valid.token'},
        )
        assert response.status_code == 401

    def test_missing_bearer_prefix_returns_401(self, client, sample_user):
        """An Authorization header without 'Bearer ' prefix should not bypass auth."""
        response = client.post(
            '/api/auth/reset-password',
            data=_reset_payload(sample_user.email, 'NewPassword1!'),
            headers={**CONTENT_JSON, 'Authorization': 'NotBearer sometoken'},
        )
        # The server may fall through to a 401 or 400; crucially it must NOT be 200.
        assert response.status_code != 200

    def test_empty_authorization_header_returns_401(self, client, sample_user):
        """An empty Authorization header value must not grant access."""
        response = client.post(
            '/api/auth/reset-password',
            data=_reset_payload(sample_user.email, 'NewPassword1!'),
            headers={**CONTENT_JSON, 'Authorization': ''},
        )
        assert response.status_code != 200


# ---------------------------------------------------------------------------
# reset-password: ownership enforcement
# ---------------------------------------------------------------------------

class TestResetPasswordOwnershipEnforcement:
    """Authenticated users MUST NOT be able to reset another user's password."""

    def test_reset_own_password_succeeds(self, client, sample_user, auth_headers):
        """Authenticated user can reset their own password."""
        response = client.post(
            '/api/auth/reset-password',
            data=_reset_payload(sample_user.email, 'MyNewSecurePassword99!'),
            headers={**CONTENT_JSON, **auth_headers},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data.get('message') == 'Password reset successfully'

    def test_reset_other_users_password_returns_403(
        self, client, sample_user, admin_user, auth_headers
    ):
        """A user authenticated as sample_user must NOT reset admin_user's password."""
        response = client.post(
            '/api/auth/reset-password',
            data=_reset_payload(admin_user.email, 'HackedPassword1!'),
            headers={**CONTENT_JSON, **auth_headers},
        )
        assert response.status_code == 403, (
            'Cross-account password reset must be forbidden; got %d' % response.status_code
        )

    def test_admin_reset_other_users_password_returns_403(
        self, client, sample_user, admin_auth_headers
    ):
        """Even an admin cannot use this endpoint to reset another user's password."""
        response = client.post(
            '/api/auth/reset-password',
            data=_reset_payload(sample_user.email, 'AdminForced1!'),
            headers={**CONTENT_JSON, **admin_auth_headers},
        )
        assert response.status_code == 403

    def test_case_insensitive_email_matching(self, client, sample_user, auth_headers):
        """Email comparison must be case-insensitive so mixed-case variants still match."""
        mixed_case_email = sample_user.email.upper()
        response = client.post(
            '/api/auth/reset-password',
            data=_reset_payload(mixed_case_email, 'CaseInsensitive1!'),
            headers={**CONTENT_JSON, **auth_headers},
        )
        # Mixed-case of the user's own email must succeed (not 403)
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# reset-password: input validation
# ---------------------------------------------------------------------------

class TestResetPasswordInputValidation:
    """Missing / malformed request fields must return 400, not 500."""

    def test_missing_new_password_returns_400(self, client, sample_user, auth_headers):
        """Request without new_password field must return 400."""
        response = client.post(
            '/api/auth/reset-password',
            data=json.dumps({'email': sample_user.email}),
            headers={**CONTENT_JSON, **auth_headers},
        )
        assert response.status_code == 400

    def test_missing_email_returns_400(self, client, sample_user, auth_headers):
        """Request without email field must return 400."""
        response = client.post(
            '/api/auth/reset-password',
            data=json.dumps({'new_password': 'SomePassword1!'}),
            headers={**CONTENT_JSON, **auth_headers},
        )
        assert response.status_code == 400

    def test_empty_body_returns_400(self, client, sample_user, auth_headers):
        """Completely empty JSON body must return 400."""
        response = client.post(
            '/api/auth/reset-password',
            data=json.dumps({}),
            headers={**CONTENT_JSON, **auth_headers},
        )
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# reset-password: functional correctness after a successful reset
# ---------------------------------------------------------------------------

class TestResetPasswordFunctional:
    """Verify that the new password actually takes effect after a reset."""

    def test_new_password_works_for_login(self, client, sample_user, auth_headers):
        """After resetting, the user should be able to log in with the new password."""
        new_password = 'BrandNewPassword42!'

        # 1. Reset the password
        reset_resp = client.post(
            '/api/auth/reset-password',
            data=_reset_payload(sample_user.email, new_password),
            headers={**CONTENT_JSON, **auth_headers},
        )
        assert reset_resp.status_code == 200

        # 2. Log in with the new password
        login_resp = client.post(
            '/api/auth/login',
            data=json.dumps({'username': sample_user.username, 'password': new_password}),
            headers=CONTENT_JSON,
        )
        assert login_resp.status_code == 200
        login_data = login_resp.get_json()
        assert 'token' in login_data

    def test_old_password_rejected_after_reset(self, client, sample_user, auth_headers):
        """After a password reset, the old password must no longer be accepted."""
        old_password = 'password123'   # set in the sample_user fixture
        new_password = 'FreshPassword77!'

        # Reset
        reset_resp = client.post(
            '/api/auth/reset-password',
            data=_reset_payload(sample_user.email, new_password),
            headers={**CONTENT_JSON, **auth_headers},
        )
        assert reset_resp.status_code == 200

        # Old password should now fail
        login_resp = client.post(
            '/api/auth/login',
            data=json.dumps({'username': sample_user.username, 'password': old_password}),
            headers=CONTENT_JSON,
        )
        assert login_resp.status_code == 401
