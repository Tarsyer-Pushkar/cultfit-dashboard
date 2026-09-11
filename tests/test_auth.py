"""
Auth tests for the cultfit-dashboard.

Uses mongomock to back _get_db() and Flask's test client.
Run: pytest tests/test_auth.py -v
"""

import sys, os, json
from datetime import datetime, timedelta
from unittest.mock import patch

import bcrypt
import mongomock
import pytest

# ── Ensure the project root is importable ────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# ── Patch _get_db before importing the app ───────────────────────────────────
_mock_client = mongomock.MongoClient()
_mock_db = _mock_client['test_cultfit']

def _mock_get_db():
    return _mock_db

# Patch at module-level before app import
import app as app_module
app_module._get_db = _mock_get_db
app_module._mongo_db = _mock_db

# ── Helpers ──────────────────────────────────────────────────────────────────
PASSWORD = 'TestPassword123!'
PASSWORD_HASH = bcrypt.hashpw(PASSWORD.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def make_user(username='testuser', role='user', is_active=True,
              force_password_change=False, password=None, expires_in_days=30):
    pw = password or PASSWORD
    pw_hash = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    now = datetime.utcnow()
    return {
        'username':              username,
        'email':                 f'{username}@test.com',
        'password_hash':         pw_hash,
        'role':                  role,
        'is_active':             is_active,
        'force_password_change': force_password_change,
        'password_changed_at':   now,
        'password_expires_at':   now + timedelta(days=expires_in_days),
        'created_at':            now,
        'updated_at':            now,
    }


@pytest.fixture(autouse=True)
def clean_db():
    """Drop all test collections before each test."""
    for name in _mock_db.list_collection_names():
        _mock_db.drop_collection(name)
    yield


@pytest.fixture
def client():
    app_module.app.config['TESTING'] = True
    app_module.app.config['SECRET_KEY'] = 'test-secret-key'
    with app_module.app.test_client() as c:
        yield c


def login(client, username, password):
    return client.post('/api/login',
                       data=json.dumps({'username': username, 'password': password}),
                       content_type='application/json')


# ── Tests ────────────────────────────────────────────────────────────────────

class TestLogin:
    def test_login_success(self, client):
        _mock_db['users'].insert_one(make_user('alice'))
        r = login(client, 'alice', PASSWORD)
        d = r.get_json()
        assert r.status_code == 200
        assert d['success'] is True
        assert d['username'] == 'alice'

    def test_login_wrong_password(self, client):
        _mock_db['users'].insert_one(make_user('bob'))
        r = login(client, 'bob', 'wrongpassword1234')
        assert r.status_code == 401
        assert r.get_json()['success'] is False

    def test_login_disabled_user(self, client):
        _mock_db['users'].insert_one(make_user('charlie', is_active=False))
        r = login(client, 'charlie', PASSWORD)
        d = r.get_json()
        assert r.status_code == 401
        assert d.get('code') == 'ACCOUNT_DISABLED'

    def test_login_expired_password(self, client):
        _mock_db['users'].insert_one(make_user('dave', expires_in_days=-1))
        r = login(client, 'dave', PASSWORD)
        d = r.get_json()
        assert r.status_code == 401
        assert d.get('code') == 'PASSWORD_CHANGE_REQUIRED'

    def test_login_forced_change(self, client):
        _mock_db['users'].insert_one(make_user('eve', force_password_change=True))
        r = login(client, 'eve', PASSWORD)
        d = r.get_json()
        assert r.status_code == 401
        assert d.get('code') == 'PASSWORD_CHANGE_REQUIRED'


class TestPerRequestRecheck:
    def test_disabled_mid_session(self, client):
        """Mutate DB mid-session, confirm next request is blocked."""
        user_doc = make_user('frank')
        result = _mock_db['users'].insert_one(user_doc)

        # Login
        r = login(client, 'frank', PASSWORD)
        assert r.status_code == 200

        # Access a protected endpoint (stores) — should work
        r = client.get('/api/cultfit/stores')
        assert r.status_code == 200

        # Disable the user in the DB
        _mock_db['users'].update_one({'_id': result.inserted_id}, {'$set': {'is_active': False}})

        # Next request should be blocked
        r = client.get('/api/cultfit/stores')
        assert r.status_code == 401
        assert r.get_json().get('code') == 'ACCOUNT_DISABLED'

    def test_expired_mid_session(self, client):
        user_doc = make_user('grace')
        result = _mock_db['users'].insert_one(user_doc)

        r = login(client, 'grace', PASSWORD)
        assert r.status_code == 200

        r = client.get('/api/cultfit/stores')
        assert r.status_code == 200

        # Expire the password
        _mock_db['users'].update_one(
            {'_id': result.inserted_id},
            {'$set': {'password_expires_at': datetime.utcnow() - timedelta(days=1)}}
        )

        r = client.get('/api/cultfit/stores')
        assert r.status_code == 401
        assert r.get_json().get('code') == 'PASSWORD_CHANGE_REQUIRED'


class TestChangePassword:
    def test_change_password_resets_expiry(self, client):
        _mock_db['users'].insert_one(make_user('hank', force_password_change=True))

        # Login (gets PASSWORD_CHANGE_REQUIRED, but session is set)
        r = login(client, 'hank', PASSWORD)
        assert r.status_code == 401
        assert r.get_json().get('code') == 'PASSWORD_CHANGE_REQUIRED'

        # Change password
        new_pw = 'NewSecurePass123!'
        r = client.post('/api/auth/change-password',
                        data=json.dumps({
                            'current_password': PASSWORD,
                            'new_password': new_pw,
                            'confirm_password': new_pw,
                        }),
                        content_type='application/json')
        d = r.get_json()
        assert r.status_code == 200
        assert d['success'] is True

        # Now should be able to access protected routes
        r = client.get('/api/cultfit/stores')
        # May get 200 (success) or 503 (DB), but not 401
        assert r.status_code != 401

    def test_policy_rejects_short_password(self, client):
        _mock_db['users'].insert_one(make_user('ida'))
        login(client, 'ida', PASSWORD)

        r = client.post('/api/auth/change-password',
                        data=json.dumps({
                            'current_password': PASSWORD,
                            'new_password': 'short',
                            'confirm_password': 'short',
                        }),
                        content_type='application/json')
        assert r.status_code == 400
        assert 'at least 12' in r.get_json()['error']

    def test_policy_rejects_same_password(self, client):
        _mock_db['users'].insert_one(make_user('jan'))
        login(client, 'jan', PASSWORD)

        r = client.post('/api/auth/change-password',
                        data=json.dumps({
                            'current_password': PASSWORD,
                            'new_password': PASSWORD,
                            'confirm_password': PASSWORD,
                        }),
                        content_type='application/json')
        assert r.status_code == 400
        assert 'different' in r.get_json()['error']


class TestAdminRoutes:
    def test_non_admin_gets_403(self, client):
        _mock_db['users'].insert_one(make_user('user1', role='user'))
        login(client, 'user1', PASSWORD)

        r = client.get('/api/admin/users')
        assert r.status_code == 403
        assert r.get_json().get('code') == 'FORBIDDEN'

    def test_admin_can_list_users(self, client):
        _mock_db['users'].insert_one(make_user('admin1', role='admin'))
        _mock_db['users'].insert_one(make_user('user2', role='user'))
        login(client, 'admin1', PASSWORD)

        r = client.get('/api/admin/users')
        assert r.status_code == 200
        users = r.get_json()['users']
        assert len(users) == 2

    def test_admin_create_and_reset(self, client):
        _mock_db['users'].insert_one(make_user('admin2', role='admin'))
        login(client, 'admin2', PASSWORD)

        # Create user
        r = client.post('/api/admin/users',
                        data=json.dumps({
                            'username': 'newuser',
                            'email': 'new@test.com',
                            'role': 'user',
                            'password': 'SecureNewPass123!',
                            'force_password_change': True,
                        }),
                        content_type='application/json')
        assert r.status_code == 201
        d = r.get_json()
        assert d['success'] is True
        new_user_id = d['user']['id']

        # Reset password
        r = client.post(f'/api/admin/users/{new_user_id}/reset-password',
                        data=json.dumps({'password': 'ResetPassword123!'}),
                        content_type='application/json')
        assert r.status_code == 200
        assert r.get_json()['success'] is True


class TestPasswordHashNeverLeaked:
    def test_hash_not_in_me(self, client):
        _mock_db['users'].insert_one(make_user('leak1'))
        login(client, 'leak1', PASSWORD)

        r = client.get('/api/me')
        body = r.get_data(as_text=True)
        assert 'password_hash' not in body
        assert '$2b$' not in body

    def test_hash_not_in_admin_list(self, client):
        _mock_db['users'].insert_one(make_user('admin3', role='admin'))
        _mock_db['users'].insert_one(make_user('leak2'))
        login(client, 'admin3', PASSWORD)

        r = client.get('/api/admin/users')
        body = r.get_data(as_text=True)
        assert 'password_hash' not in body
        assert '$2b$' not in body

    def test_hash_not_in_create_response(self, client):
        _mock_db['users'].insert_one(make_user('admin4', role='admin'))
        login(client, 'admin4', PASSWORD)

        r = client.post('/api/admin/users',
                        data=json.dumps({
                            'username': 'leak3',
                            'password': 'SecureNewPass123!',
                            'role': 'user',
                        }),
                        content_type='application/json')
        body = r.get_data(as_text=True)
        assert 'password_hash' not in body
        assert '$2b$' not in body
