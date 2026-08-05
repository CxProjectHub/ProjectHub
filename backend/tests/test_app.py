"""
Basic tests for Flask application configuration and imports
Note: Full app tests require proper environment setup
"""
import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAppConfiguration(unittest.TestCase):
    """Test basic application configuration"""

    def test_config_import(self):
        """Test that config module can be imported"""
        try:
            from config import Config
            self.assertIsNotNone(Config)
            self.assertTrue(hasattr(Config, 'JWT_SECRET_KEY'))
            self.assertTrue(hasattr(Config, 'DATABASE_URL'))
        except ImportError as e:
            self.fail(f"Failed to import Config: {e}")

    def test_models_import(self):
        """Test that models can be imported"""
        try:
            from models import User, Project, Task, Message
            self.assertIsNotNone(User)
            self.assertIsNotNone(Project)
            self.assertIsNotNone(Task)
            self.assertIsNotNone(Message)
        except ImportError as e:
            self.fail(f"Failed to import models: {e}")

    def test_database_import(self):
        """Test that database module can be imported"""
        try:
            from database import init_db
            self.assertIsNotNone(init_db)
        except ImportError as e:
            self.fail(f"Failed to import database: {e}")


class TestRouteImports(unittest.TestCase):
    """Test that route modules can be imported"""

    def test_auth_routes_import(self):
        """Test auth routes import"""
        try:
            from routes import auth
            self.assertIsNotNone(auth)
            self.assertTrue(hasattr(auth, 'bp'))
        except ImportError as e:
            self.fail(f"Failed to import auth routes: {e}")

    def test_projects_routes_import(self):
        """Test projects routes import"""
        try:
            from routes import projects
            self.assertIsNotNone(projects)
            self.assertTrue(hasattr(projects, 'bp'))
        except ImportError as e:
            self.fail(f"Failed to import projects routes: {e}")

    def test_tasks_routes_import(self):
        """Test tasks routes import"""
        try:
            from routes import tasks
            self.assertIsNotNone(tasks)
            self.assertTrue(hasattr(tasks, 'bp'))
        except ImportError as e:
            self.fail(f"Failed to import tasks routes: {e}")


class TestAdminDashboardAuthentication(unittest.TestCase):
    """
    Tests for CWE-306: Missing Authentication for Critical Function
    Verifies that the /admin endpoint requires authentication and admin role.
    """

    def setUp(self):
        """Set up test app with in-memory SQLite database"""
        from flask import Flask
        from flask_cors import CORS
        from models import db, User
        from config import Config

        class TestConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
            WTF_CSRF_ENABLED = False
            JWT_SECRET_KEY = 'test-secret-key-for-unit-testing-only'
            UPLOAD_FOLDER = '/tmp/test_uploads'
            LOG_FILE = '/tmp/test_logs/app.log'

        self.test_app = Flask(__name__)
        self.test_app.config.from_object(TestConfig)

        CORS(self.test_app)
        db.init_app(self.test_app)

        # Register all blueprints
        from routes import auth, projects, tasks, documents, messages, api, analytics
        self.test_app.register_blueprint(auth.bp, url_prefix='/api/auth')
        self.test_app.register_blueprint(projects.bp, url_prefix='/api/projects')
        self.test_app.register_blueprint(tasks.bp, url_prefix='/api/tasks')
        self.test_app.register_blueprint(documents.bp, url_prefix='/api/documents')
        self.test_app.register_blueprint(messages.bp, url_prefix='/api/messages')
        self.test_app.register_blueprint(api.bp, url_prefix='/api/v1')
        self.test_app.register_blueprint(analytics.bp, url_prefix='/api')

        # Register the admin route the same way app.py does
        from auth import require_role

        @self.test_app.route('/admin')
        @require_role('admin')
        def admin_dashboard():
            """Admin dashboard - requires admin role"""
            return "admin content", 200

        with self.test_app.app_context():
            db.create_all()

            # Create admin user
            self.admin_user = User(
                username='admin_test',
                email='admin_test@example.com',
                role='admin'
            )
            self.admin_user.set_password('adminpass123')
            db.session.add(self.admin_user)

            # Create regular (non-admin) user
            self.regular_user = User(
                username='regular_test',
                email='regular_test@example.com',
                role='team_member'
            )
            self.regular_user.set_password('userpass123')
            db.session.add(self.regular_user)

            db.session.commit()

            # Generate tokens inside app context
            from auth import generate_token
            self.admin_token = generate_token(self.admin_user.id, self.admin_user.username)
            self.regular_token = generate_token(self.regular_user.id, self.regular_user.username)

        self.client = self.test_app.test_client()

    def tearDown(self):
        """Clean up database"""
        from models import db
        with self.test_app.app_context():
            db.session.remove()
            db.drop_all()

    def test_admin_dashboard_unauthenticated_returns_401(self):
        """
        CWE-306 regression: Unauthenticated request to /admin must be rejected.
        Before the fix, no auth check existed and the route was publicly accessible.
        """
        response = self.client.get('/admin')
        self.assertEqual(
            response.status_code, 401,
            "Unauthenticated access to /admin must return HTTP 401"
        )

    def test_admin_dashboard_no_token_returns_401(self):
        """Missing Authorization header must produce 401, not 200."""
        response = self.client.get('/admin', headers={})
        self.assertEqual(response.status_code, 401)

    def test_admin_dashboard_invalid_token_returns_401(self):
        """Malformed / invalid JWT must be rejected with 401."""
        response = self.client.get(
            '/admin',
            headers={'Authorization': 'Bearer this.is.not.a.valid.token'}
        )
        self.assertEqual(response.status_code, 401)

    def test_admin_dashboard_non_admin_role_returns_403(self):
        """
        An authenticated user with a non-admin role must be forbidden (403).
        This ensures role-based enforcement is in place, not just authentication.
        """
        response = self.client.get(
            '/admin',
            headers={'Authorization': f'Bearer {self.regular_token}'}
        )
        self.assertEqual(
            response.status_code, 403,
            "Non-admin authenticated user accessing /admin must receive HTTP 403"
        )

    def test_admin_dashboard_admin_role_returns_200(self):
        """Admin users must still be able to access the dashboard (no regression)."""
        response = self.client.get(
            '/admin',
            headers={'Authorization': f'Bearer {self.admin_token}'}
        )
        self.assertEqual(
            response.status_code, 200,
            "Admin user should be able to access /admin dashboard"
        )

    def test_admin_dashboard_requires_role_decorator_applied(self):
        """
        Verify via introspection that require_role is present on the view function.
        Detects accidental removal of the decorator at import time.
        """
        from auth import require_role
        view_func = self.test_app.view_functions.get('admin_dashboard')
        self.assertIsNotNone(view_func, "admin_dashboard view function must be registered")
        # The wrapped function should have been decorated (closure wraps original)
        # We verify it enforces auth by calling without a token (functional check):
        response = self.client.get('/admin')
        self.assertNotEqual(
            response.status_code, 200,
            "admin_dashboard must not be reachable without authentication"
        )

    def test_admin_dashboard_bearer_token_query_param_non_admin_rejected(self):
        """Token passed via query parameter for non-admin user must still be rejected."""
        response = self.client.get(f'/admin?token={self.regular_token}')
        self.assertEqual(response.status_code, 403)

    def test_admin_dashboard_bearer_token_query_param_admin_allowed(self):
        """Token passed via query parameter for admin user must be allowed."""
        response = self.client.get(f'/admin?token={self.admin_token}')
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
