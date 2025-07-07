#!/usr/bin/env python
"""Tests for token creation functionality in py-gitea

This test suite validates:
1. User token creation with read-only scopes
2. Admin token creation with admin-level scopes  
3. Token authentication and functionality
4. Error handling for invalid credentials

Test Setup:
- Requires Gitea instance running at http://localhost:3000
- Uses environment variables or .env file for admin credentials
- Creates test users and validates token functionality
"""

import os
import uuid
import pytest
import time

from gitea import (
    Gitea,
    User,
    Organization,
    Repository,
    NotFoundException,
    AlreadyExistsException
)


@pytest.fixture
def admin_instance(scope="module"):
    """Setup admin Gitea instance for testing token creation"""
    # Try to get credentials from environment
    url = os.getenv("GITEA_ROOT_URL", "http://localhost:3000")
    admin_username = os.getenv("GITEA_ADMIN_USERNAME")
    admin_password = os.getenv("GITEA_ADMIN_PASSWORD")
    
    if not admin_username or not admin_password:
        pytest.fail("GITEA_ADMIN_USERNAME and GITEA_ADMIN_PASSWORD environment variables are required")
    
    try:
        # Create admin instance with basic auth
        g = Gitea(url, auth=(admin_username, admin_password), verify=False)
        print(f"Gitea Version: {g.get_version()}")
        print(f"Admin user: {g.get_user().username}")
        return g
    except Exception as e:
        pytest.fail(f"Could not connect to Gitea instance at {url}: {e}")


@pytest.fixture
def test_user_data():
    """Generate unique test user data"""
    unique_id = uuid.uuid4().hex[:8]
    return {
        "username": f"testuser_{unique_id}",
        "email": f"testuser_{unique_id}@example.com",
        "password": f"TestPassword123_{unique_id}",
        "full_name": f"Test User {unique_id}"
    }


@pytest.fixture
def created_test_user(admin_instance, test_user_data):
    """Create a test user and clean up after test"""
    user = admin_instance.create_user(
        user_name=test_user_data["username"],
        email=test_user_data["email"],
        password=test_user_data["password"],
        full_name=test_user_data["full_name"],
        change_pw=False,
        send_notify=False
    )
    
    yield user, test_user_data
    
    # Cleanup: delete the test user
    try:
        user.delete()
    except Exception as e:
        print(f"Warning: Could not delete test user {user.username}: {e}")


class TestUserTokenCreation:
    """Test User.create_token() method"""
    
    def test_create_user_token_default_scopes(self, created_test_user):
        """Test creating a user token with default read-only scopes"""
        user, user_data = created_test_user
        
        # Create token with default scopes
        token = user.create_token(
            password=user_data["password"],
            name=f"test_token_{int(time.time())}"
        )
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Verify token works by creating a new Gitea instance with it
        token_gitea = Gitea("http://localhost:3000", token_text=token, verify=False)
        token_user = token_gitea.get_user()
        assert token_user.username == user.username
    
    def test_create_user_token_custom_scopes(self, created_test_user):
        """Test creating a user token with custom scopes"""
        user, user_data = created_test_user
        
        custom_scopes = ["read:user", "read:repository"]
        token = user.create_token(
            password=user_data["password"],
            name=f"custom_token_{int(time.time())}",
            scopes=custom_scopes
        )
        
        assert token is not None
        assert isinstance(token, str)
        
        # Verify token works
        token_gitea = Gitea("http://localhost:3000", token_text=token, verify=False)
        token_user = token_gitea.get_user()
        assert token_user.username == user.username
    
    def test_create_user_token_invalid_password(self, created_test_user):
        """Test token creation fails with wrong password"""
        user, user_data = created_test_user
        
        with pytest.raises(Exception):
            user.create_token(
                password="wrong_password",
                name=f"fail_token_{int(time.time())}"
            )
    
    def test_create_user_token_custom_name(self, created_test_user):
        """Test creating a user token with custom name"""
        user, user_data = created_test_user
        
        custom_name = f"my_custom_token_{int(time.time())}"
        token = user.create_token(
            password=user_data["password"],
            name=custom_name
        )
        
        assert token is not None
        assert isinstance(token, str)


class TestAdminTokenCreation:
    """Test Gitea.create_admin_token() method"""
    
    def test_create_admin_token(self, admin_instance, created_test_user):
        """Test creating an admin token for a user"""
        user, user_data = created_test_user
        
        # Create admin token
        admin_token = admin_instance.create_admin_token(
            user=user,
            password=user_data["password"],
            name=f"admin_token_{int(time.time())}"
        )
        
        assert admin_token is not None
        assert isinstance(admin_token, str)
        assert len(admin_token) > 0
        
        # Verify admin token works and has admin privileges
        admin_token_gitea = Gitea("http://localhost:3000", token_text=admin_token, verify=False)
        token_user = admin_token_gitea.get_user()
        assert token_user.username == user.username
        
        # Try an admin operation (create a user) to verify admin scope
        try:
            temp_user_data = {
                "username": f"temp_{uuid.uuid4().hex[:6]}",
                "email": f"temp_{uuid.uuid4().hex[:6]}@example.com",
                "password": "TempPassword123"
            }
            
            temp_user = admin_token_gitea.create_user(
                user_name=temp_user_data["username"],
                email=temp_user_data["email"],
                password=temp_user_data["password"]
            )
            
            # Clean up temp user
            temp_user.delete()
            
        except Exception as e:
            pytest.fail(f"Admin token should allow user creation: {e}")
    
    def test_create_admin_token_invalid_password(self, admin_instance, created_test_user):
        """Test admin token creation fails with wrong password"""
        user, user_data = created_test_user
        
        with pytest.raises(Exception):
            admin_instance.create_admin_token(
                user=user,
                password="wrong_password",
                name=f"fail_admin_token_{int(time.time())}"
            )
    
    def test_create_admin_token_custom_name(self, admin_instance, created_test_user):
        """Test creating admin token with custom name"""
        user, user_data = created_test_user
        
        custom_name = f"my_admin_token_{int(time.time())}"
        admin_token = admin_instance.create_admin_token(
            user=user,
            password=user_data["password"],
            name=custom_name
        )
        
        assert admin_token is not None
        assert isinstance(admin_token, str)


class TestTokenFunctionality:
    """Test that created tokens actually work for API operations"""
    
    def test_user_token_read_operations(self, created_test_user):
        """Test that user tokens can perform read operations"""
        user, user_data = created_test_user
        
        # Create user token
        token = user.create_token(
            password=user_data["password"],
            name=f"read_test_{int(time.time())}"
        )
        
        # Test read operations with token
        token_gitea = Gitea("http://localhost:3000", token_text=token, verify=False)
        
        # Should be able to get user info
        token_user = token_gitea.get_user()
        assert token_user.username == user.username
        
        # Should be able to get user's repositories
        repos = token_user.get_repositories()
        assert isinstance(repos, list)
    
    def test_admin_token_write_operations(self, admin_instance, created_test_user):
        """Test that admin tokens can perform write operations"""
        user, user_data = created_test_user
        
        # Create admin token
        admin_token = admin_instance.create_admin_token(
            user=user,
            password=user_data["password"],
            name=f"write_test_{int(time.time())}"
        )
        
        # Test write operations with admin token
        admin_token_gitea = Gitea("http://localhost:3000", token_text=admin_token, verify=False)
        
        # Should be able to create a repository
        repo_name = f"test_repo_{uuid.uuid4().hex[:8]}"
        try:
            repo = admin_token_gitea.get_user().create_repo(
                repoName=repo_name,
                description="Test repository created by admin token",
                private=True
            )
            
            assert repo.name == repo_name
            assert repo.description == "Test repository created by admin token"
            
            # Clean up
            repo.delete()
            
        except Exception as e:
            pytest.fail(f"Admin token should allow repository creation: {e}")


class TestTokenAuthentication:
    """Test token-based authentication"""
    
    def test_token_vs_basic_auth_equivalence(self, admin_instance, created_test_user):
        """Test that token auth provides same access as basic auth"""
        user, user_data = created_test_user
        
        # Create token
        token = user.create_token(
            password=user_data["password"],
            name=f"auth_test_{int(time.time())}"
        )
        
        # Test with basic auth
        basic_auth_gitea = Gitea(
            "http://localhost:3000", 
            auth=(user.username, user_data["password"]), 
            verify=False
        )
        basic_user = basic_auth_gitea.get_user()
        
        # Test with token auth
        token_gitea = Gitea("http://localhost:3000", token_text=token, verify=False)
        token_user = token_gitea.get_user()
        
        # Should get same user info
        assert basic_user.username == token_user.username
        assert basic_user.email == token_user.email
        assert basic_user.id == token_user.id


if __name__ == "__main__":
    pytest.main([__file__])