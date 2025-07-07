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


def test_user_token_creation(test_user):
    user, user_data = test_user
    
    token = user.create_token(password=user_data["password"])
    
    assert token
    assert isinstance(token, str)
    
    # Verify token works
    token_gitea = Gitea("http://localhost:3000", token_text=token, verify=False)
    assert token_gitea.get_user().username == user.username


def test_user_token_custom_scopes(test_user):
    user, user_data = test_user
    
    token = user.create_token(
        password=user_data["password"],
        scopes=["read:user"]
    )
    
    assert token
    token_gitea = Gitea("http://localhost:3000", token_text=token, verify=False)
    assert token_gitea.get_user().username == user.username


def test_user_token_invalid_password(test_user):
    user, user_data = test_user
    
    with pytest.raises(Exception):
        user.create_token(password="wrong_password")


def test_admin_token_creation(admin_instance, test_user):
    user, user_data = test_user
    
    admin_token = admin_instance.create_admin_token(
        user=user,
        password=user_data["password"]
    )
    
    assert admin_token
    assert isinstance(admin_token, str)
    
    # Verify admin token works
    admin_gitea = Gitea("http://localhost:3000", token_text=admin_token, verify=False)
    assert admin_gitea.get_user().username == user.username


def test_admin_token_has_admin_privileges(admin_instance, test_user):
    user, user_data = test_user
    
    admin_token = admin_instance.create_admin_token(
        user=user,
        password=user_data["password"]
    )
    
    # Test admin operation with token
    admin_gitea = Gitea("http://localhost:3000", token_text=admin_token, verify=False)
    
    temp_uid = uuid.uuid4().hex[:6]
    temp_user = admin_gitea.create_user(
        user_name=f"temp_{temp_uid}",
        email=f"temp_{temp_uid}@example.com",
        password="TempPass123"
    )
    
    temp_user.delete()


def test_admin_token_invalid_password(admin_instance, test_user):
    user, user_data = test_user
    
    with pytest.raises(Exception):
        admin_instance.create_admin_token(
            user=user,
            password="wrong_password"
        )