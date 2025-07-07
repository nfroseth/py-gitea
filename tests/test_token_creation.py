import os
import uuid
import pytest
from gitea import Gitea


@pytest.fixture(scope="module")
def admin_instance():
    url = os.getenv("GITEA_ROOT_URL", "http://localhost:3000")
    username = os.getenv("GITEA_ADMIN_USERNAME")
    password = os.getenv("GITEA_ADMIN_PASSWORD")
    
    if not username or not password:
        pytest.fail("GITEA_ADMIN_USERNAME and GITEA_ADMIN_PASSWORD required")
    
    return Gitea(url, auth=(username, password), verify=False)


@pytest.fixture
def test_user(admin_instance):
    uid = uuid.uuid4().hex[:8]
    user_data = {
        "username": f"testuser_{uid}",
        "email": f"test_{uid}@example.com", 
        "password": f"TestPass123_{uid}"
    }
    
    user = admin_instance.create_user(
        user_name=user_data["username"],
        email=user_data["email"],
        password=user_data["password"],
        change_pw=False
    )
    
    yield user, user_data
    
    try:
        user.delete()
    except:
        pass


class TestUserTokens:
    """Test User.create_token() method and token functionality"""
    
    def test_create_token_with_default_read_scopes(self, test_user):
        """User token creation with default read-only scopes"""
        user, user_data = test_user
        
        token = user.create_token(password=user_data["password"])
        
        assert token and len(token) > 20  # Gitea tokens are typically 40+ chars
        
        # Token authenticates correctly
        token_gitea = Gitea("http://localhost:3000", token_text=token, verify=False)
        token_user = token_gitea.get_user()
        assert token_user.username == user.username
        assert token_user.id == user.id
    
    def test_read_token_can_read_but_not_write(self, test_user):
        """Read-only tokens can access read operations but fail on write operations"""
        user, user_data = test_user
        
        # Create read-only token
        read_token = user.create_token(
            password=user_data["password"],
            scopes=["read:user", "read:repository"]
        )
        
        read_gitea = Gitea("http://localhost:3000", token_text=read_token, verify=False)
        
        # Should be able to read user info
        read_user = read_gitea.get_user()
        assert read_user.username == user.username
        
        # Should be able to list repositories
        repos = read_user.get_repositories()
        assert isinstance(repos, list)
        
        # Should NOT be able to create repositories (write operation)
        with pytest.raises(Exception):
            read_user.create_repo(
                repoName=f"test_repo_{uuid.uuid4().hex[:8]}",
                description="Should fail"
            )
    
    def test_token_creation_with_custom_name_and_scopes(self, test_user):
        """Custom token names and specific scopes work correctly"""
        user, user_data = test_user
        
        custom_name = f"my_api_token_{uuid.uuid4().hex[:6]}"
        token = user.create_token(
            password=user_data["password"],
            name=custom_name,
            scopes=["read:user", "read:organization"]
        )
        
        assert token
        
        # Verify token works for specified scopes
        token_gitea = Gitea("http://localhost:3000", token_text=token, verify=False)
        assert token_gitea.get_user().username == user.username
    
    def test_token_creation_fails_with_wrong_password(self, test_user):
        """Token creation properly validates user password"""
        user, user_data = test_user
        
        with pytest.raises(Exception) as exc_info:
            user.create_token(password="definitely_wrong_password")
        
        # Should be an authentication-related error
        assert exc_info.value


class TestAdminTokens:
    """Test Gitea.create_admin_token() method and admin privileges"""
    
    def test_create_admin_token(self, admin_instance, test_user):
        """Admin can create admin-level tokens for users"""
        user, user_data = test_user
        
        admin_token = admin_instance.create_admin_token(
            user=user,
            password=user_data["password"]
        )
        
        assert admin_token and len(admin_token) > 20
        
        # Token authenticates as the target user
        admin_gitea = Gitea("http://localhost:3000", token_text=admin_token, verify=False)
        token_user = admin_gitea.get_user()
        assert token_user.username == user.username
    
    def test_admin_token_has_write_privileges(self, admin_instance, test_user):
        """Admin tokens can perform write operations"""
        user, user_data = test_user
        
        admin_token = admin_instance.create_admin_token(
            user=user,
            password=user_data["password"]
        )
        
        admin_gitea = Gitea("http://localhost:3000", token_text=admin_token, verify=False)
        
        # Should be able to create a repository
        repo_name = f"admin_test_repo_{uuid.uuid4().hex[:8]}"
        repo = admin_gitea.get_user().create_repo(
            repoName=repo_name,
            description="Created by admin token",
            private=True
        )
        
        assert repo.name == repo_name
        assert repo.private is True
        
        # Clean up
        repo.delete()
    
    def test_admin_token_can_create_users(self, admin_instance, test_user):
        """Admin tokens can perform admin operations like user creation"""
        user, user_data = test_user
        
        admin_token = admin_instance.create_admin_token(
            user=user,
            password=user_data["password"]
        )
        
        admin_gitea = Gitea("http://localhost:3000", token_text=admin_token, verify=False)
        
        # Should be able to create another user (admin operation)
        temp_uid = uuid.uuid4().hex[:6]
        temp_user = admin_gitea.create_user(
            user_name=f"admin_created_{temp_uid}",
            email=f"admin_{temp_uid}@example.com",
            password="AdminCreated123"
        )
        
        assert temp_user.username == f"admin_created_{temp_uid}"
        
        # Clean up
        temp_user.delete()
    
    def test_admin_token_creation_validates_password(self, admin_instance, test_user):
        """Admin token creation validates the user's password"""
        user, user_data = test_user
        
        with pytest.raises(Exception):
            admin_instance.create_admin_token(
                user=user,
                password="wrong_password"
            )


class TestTokenAuthentication:
    """Test token authentication behavior"""
    
    def test_token_auth_equivalent_to_basic_auth(self, test_user):
        """Token authentication provides same user access as basic auth"""
        user, user_data = test_user
        
        # Create token
        token = user.create_token(password=user_data["password"])
        
        # Get user info with basic auth
        basic_gitea = Gitea(
            "http://localhost:3000",
            auth=(user.username, user_data["password"]),
            verify=False
        )
        basic_user = basic_gitea.get_user()
        
        # Get user info with token auth
        token_gitea = Gitea("http://localhost:3000", token_text=token, verify=False)
        token_user = token_gitea.get_user()
        
        # Should return identical user information
        assert basic_user.username == token_user.username
        assert basic_user.email == token_user.email
        assert basic_user.id == token_user.id
    
    def test_multiple_tokens_work_independently(self, test_user):
        """Multiple tokens for same user work independently"""
        user, user_data = test_user
        
        # Create two different tokens
        token1 = user.create_token(
            password=user_data["password"],
            name="token_1"
        )
        token2 = user.create_token(
            password=user_data["password"],
            name="token_2"
        )
        
        assert token1 != token2
        
        # Both tokens should work
        gitea1 = Gitea("http://localhost:3000", token_text=token1, verify=False)
        gitea2 = Gitea("http://localhost:3000", token_text=token2, verify=False)
        
        user1 = gitea1.get_user()
        user2 = gitea2.get_user()
        
        assert user1.username == user2.username == user.username