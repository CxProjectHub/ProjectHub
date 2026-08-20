"""
Tests for admin dashboard authentication (CWE-306 remediation).

Validates that the /admin route requires authentication and enforces
the admin role — unauthenticated and non-admin requests must be rejected
before any sensitive data is queried or rendered.
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from flask_cors import CORS
from models import db, User, Project, Task
from config import Config


class TestConfig(Config):
    """Configuration used exclusively by this test module."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_POOL_SIZE = None
    SQLALCHEMY_MAX_OVERFLOW = None
    SQLALCHEMY_POOL_TIMEOUT = None
    SQLALCHEMY_POOL_RECYCLE = None
    WTF_CSRF_ENABLED = False
    # Test secret key - not used in production
    JWT_SECRET_KEY = 'test-secret-key-for-admin-auth-tests'
    UPLOAD_FOLDER = '/tmp/test_uploads_admin'
    LOG_FILE = '/tmp/test_logs_admin/app.log'


@pytest.fixture(scope='function')
def admin_app():
    """
    Create a test Flask app that includes the /admin route registered in
    the same way as the production app.py.  Blueprint registration is kept
    minimal — only routes needed for auth token generation.
    """
    test_app = Flask(__name__, template_folder=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates'
    ))
    test_app.config.from_object(TestConfig)
    CORS(test_app)
    db.init_app(test_app)

    # Register auth blueprint so token-based login flow is available
    from routes import auth as auth_bp, projects as projects_bp, tasks as tasks_bp
    from routes import documents as docs_bp, messages as msgs_bp, api as api_bp
    from routes import analytics as analytics_bp
    test_app.register_blueprint(auth_bp.bp, url_prefix='/api/auth')
    test_app.register_blueprint(projects_bp.bp, url_prefix='/api/projects')
    test_app.register_blueprint(tasks_bp.bp, url_prefix='/api/tasks')
    test_app.register_blueprint(docs_bp.bp, url_prefix='/api/documents')
    test_app.register_blueprint(msgs_bp.bp, url_prefix='/api/messages')
    test_app.register_blueprint(api_bp.bp, url_prefix='/api/v1')
    test_app.register_blueprint(analytics_bp.bp, url_prefix='/api')

    # Register the /admin route with the same decorator as production
    from auth import require_role
    from flask import render_template

    @test_app.route('/admin')
    @require_role('admin')
    def admin_dashboard():
        """Admin dashboard - requires admin role"""
        users = User.query.all()
        projects = Project.query.all()
        tasks = Task.query.all()
        return render_template(
            'admin.html',
            users=users,
            projects=projects,
            tasks=tasks,
            request_id='test-request-id',
        )

    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope='function')
def admin_client(admin_app):
    """Test client for the admin-enabled app."""
    return admin_app.test_client()


@pytest.fixture(scope='function')
def admin_db(admin_app):
    """Database session for the admin test app."""
    with admin_app.app_context():
        yield db.session


@pytest.fixture(scope='function')
def admin_user(admin_db):
    """Create an admin user."""
    user = User(username='adminuser', email='admin@example.com', role='admin')
    user.set_password('adminpass123')
    admin_db.add(user)
    admin_db.commit()
    return user


@pytest.fixture(scope='function')
def regular_user(admin_db):
    """Create a non-admin (team_member) user."""
    user = User(username='regularuser', email='regular@example.com', role='team_member')
    user.set_password('userpass123')
    admin_db.add(user)
    admin_db.commit()
    return user


@pytest.fixture(scope='function')
def pm_user(admin_db):
    """Create a project_manager user (has elevated, but not admin, role)."""
    user = User(username='pmuser', email='pm@example.com', role='project_manager')
    user.set_password('pmpass123')
    admin_db.add(user)
    admin_db.commit()
    return user


def _make_auth_headers(app, user):
    """Return Bearer token headers for the given user."""
    with app.app_context():
        from auth import generate_token
        token = generate_token(user.id, user.username)
    return {'Authorization': f'Bearer {token}'}


# ---------------------------------------------------------------------------
# Tests: unauthenticated access MUST be rejected
# ---------------------------------------------------------------------------

class TestAdminDashboardUnauthenticated:
    """The /admin endpoint must reject requests that carry no credentials."""

    def test_no_token_returns_401(self, admin_client):
        """GET /admin with no Authorization header must return 401."""
        response = admin_client.get('/admin')
        assert response.status_code == 401

    def test_no_token_json_error_message(self, admin_client):
        """Response for unauthenticated request must include an error field."""
        response = admin_client.get('/admin', content_type='application/json')
        data = response.get_json()
        assert data is not None
        assert 'error' in data

    def test_empty_bearer_token_returns_401(self, admin_client):
        """An Authorization header with an empty token value must be rejected."""
        response = admin_client.get('/admin', headers={'Authorization': 'Bearer '})
        assert response.status_code == 401

    def test_invalid_token_returns_401(self, admin_client):
        """A malformed or forged JWT must result in a 401 response."""
        response = admin_client.get(
            '/admin',
            headers={'Authorization': 'Bearer this.is.not.a.valid.jwt'},
        )
        assert response.status_code == 401

    def test_arbitrary_header_value_returns_401(self, admin_client):
        """A non-Bearer Authorization value must not bypass authentication."""
        response = admin_client.get(
            '/admin',
            headers={'Authorization': 'Basic dXNlcjpwYXNz'},
        )
        assert response.status_code == 401

    def test_sensitive_data_not_returned_without_auth(self, admin_client, admin_user):
        """Verify that user data is NOT exposed in an unauthenticated response."""
        response = admin_client.get('/admin')
        # Should not be 200 (no leak of sensitive data)
        assert response.status_code != 200


# ---------------------------------------------------------------------------
# Tests: non-admin authenticated users MUST be rejected
# ---------------------------------------------------------------------------

class TestAdminDashboardInsufficientRole:
    """Authenticated users without admin role must receive 403."""

    def test_team_member_returns_403(self, admin_app, admin_client, regular_user):
        """A team_member role must not access the admin dashboard."""
        headers = _make_auth_headers(admin_app, regular_user)
        response = admin_client.get('/admin', headers=headers)
        assert response.status_code == 403

    def test_team_member_json_error_message(self, admin_app, admin_client, regular_user):
        """A 403 response for a non-admin user must include an error field."""
        headers = _make_auth_headers(admin_app, regular_user)
        response = admin_client.get(
            '/admin', headers=headers, content_type='application/json'
        )
        data = response.get_json()
        assert data is not None
        assert 'error' in data

    def test_project_manager_returns_403(self, admin_app, admin_client, pm_user):
        """A project_manager role must not access the admin dashboard."""
        headers = _make_auth_headers(admin_app, pm_user)
        response = admin_client.get('/admin', headers=headers)
        assert response.status_code == 403

    def test_non_admin_does_not_see_sensitive_data(
        self, admin_app, admin_client, regular_user
    ):
        """A non-admin user must not receive any user-list data in the response."""
        headers = _make_auth_headers(admin_app, regular_user)
        response = admin_client.get('/admin', headers=headers)
        # Must not be a successful response
        assert response.status_code not in (200, 302)


# ---------------------------------------------------------------------------
# Tests: admin user MUST be granted access
# ---------------------------------------------------------------------------

class TestAdminDashboardAuthorized:
    """An authenticated admin user must be allowed to access the dashboard."""

    def test_admin_returns_200(self, admin_app, admin_client, admin_user):
        """An admin user with a valid token must receive a 200 response."""
        headers = _make_auth_headers(admin_app, admin_user)
        response = admin_client.get('/admin', headers=headers)
        assert response.status_code == 200

    def test_admin_response_contains_dashboard_content(
        self, admin_app, admin_client, admin_user
    ):
        """The admin dashboard response must contain rendered HTML content."""
        headers = _make_auth_headers(admin_app, admin_user)
        response = admin_client.get('/admin', headers=headers)
        assert response.status_code == 200
        # The template should produce an HTML response
        assert response.content_type.startswith('text/html')

    def test_admin_can_see_user_list(self, admin_app, admin_client, admin_user):
        """The admin dashboard must render with the admin's own user data accessible."""
        headers = _make_auth_headers(admin_app, admin_user)
        response = admin_client.get('/admin', headers=headers)
        assert response.status_code == 200
        # Admin user should be reflected in the rendered page
        assert b'adminuser' in response.data

    def test_token_via_query_param_rejected_for_non_admin(
        self, admin_app, admin_client, regular_user
    ):
        """Token passed as a query parameter for a non-admin user must still return 403."""
        with admin_app.app_context():
            from auth import generate_token
            token = generate_token(regular_user.id, regular_user.username)
        response = admin_client.get(f'/admin?token={token}')
        assert response.status_code == 403

    def test_token_via_query_param_accepted_for_admin(
        self, admin_app, admin_client, admin_user
    ):
        """Token passed as a query parameter for an admin user must still grant access."""
        with admin_app.app_context():
            from auth import generate_token
            token = generate_token(admin_user.id, admin_user.username)
        response = admin_client.get(f'/admin?token={token}')
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Tests: require_role decorator behaviour (unit-level)
# ---------------------------------------------------------------------------

class TestRequireRoleDecorator:
    """Unit tests for the require_role('admin') auth decorator in auth.py."""

    def test_require_role_returns_401_for_missing_user(self, admin_app, admin_client):
        """Confirm the decorator enforces authentication before role check."""
        response = admin_client.get('/admin')
        assert response.status_code == 401
        data = response.get_json()
        assert 'Authentication required' in data.get('error', '')

    def test_require_role_returns_403_for_wrong_role(
        self, admin_app, admin_client, regular_user
    ):
        """Confirm the decorator returns 403 when the role is insufficient."""
        headers = _make_auth_headers(admin_app, regular_user)
        response = admin_client.get('/admin', headers=headers)
        assert response.status_code == 403
        data = response.get_json()
        assert 'permissions' in data.get('error', '').lower() or 'Insufficient' in data.get('error', '')

    def test_require_role_allows_admin_role(self, admin_app, admin_client, admin_user):
        """Confirm the decorator allows a user whose role is 'admin'."""
        headers = _make_auth_headers(admin_app, admin_user)
        response = admin_client.get('/admin', headers=headers)
        assert response.status_code == 200

    def test_expired_or_tampered_token_rejected(self, admin_app, admin_client):
        """A tampered token must be rejected with a 401 before role is checked."""
        # Craft a token by encoding a payload with a wrong secret
        import jwt
        tampered = jwt.encode(
            {'user_id': 9999, 'username': 'hacker'},
            'wrong-secret',
            algorithm='HS256',
        )
        if isinstance(tampered, bytes):
            tampered = tampered.decode('utf-8')
        response = admin_client.get(
            '/admin', headers={'Authorization': f'Bearer {tampered}'}
        )
        assert response.status_code == 401
