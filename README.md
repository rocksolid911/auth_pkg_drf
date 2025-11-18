# DRF Auth Package

A production-ready, reusable Django REST Framework authentication package with support for email/password auth, phone number authentication (OTP), social logins (Google, Facebook, Twitter), and both JWT and session-based authentication.

## Features

- **Email/Password Authentication**: Complete registration, login, logout, password change, and password reset flows
- **Phone Number Authentication**: OTP-based phone verification and login
- **Social Authentication**: Login with Google, Facebook, and Twitter
- **Flexible Auth Modes**: Support for JWT-based auth, session-based auth, or both simultaneously
- **Email Verification**: Optional email verification for new users
- **Phone Verification**: Optional phone number verification with OTP
- **PostgreSQL Optimized**: Designed to work seamlessly with PostgreSQL
- **Production Ready**: Includes proper logging, security features, and error handling
- **Type Hints**: Modern Python code with type hints throughout
- **Extensible**: Easy to customize and extend for your specific needs

## Installation

### From GitHub

```bash
pip install git+https://github.com/yourusername/drf-auth-package.git
```

### From Local Repository

```bash
git clone https://github.com/yourusername/drf-auth-package.git
cd drf-auth-package
pip install -e .
```

## Quick Start

### 1. Add to INSTALLED_APPS

Add `drf_auth_package` to your Django project's `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # Django apps
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'rest_framework',

    # DRF Auth Package
    'drf_auth_package',

    # Your apps
    # ...
]
```

### 2. Set Custom User Model

In your `settings.py`:

```python
AUTH_USER_MODEL = 'drf_auth_package.User'
```

### 3. Configure Authentication Backend

Add the email authentication backend:

```python
AUTHENTICATION_BACKENDS = [
    'drf_auth_package.authentication.EmailBackend',
    'django.contrib.auth.backends.ModelBackend',
]
```

### 4. Configure DRF Authentication

Choose your authentication mode and configure DRF:

```python
# Choose: "jwt", "session", or "both"
DRF_AUTH_BACKEND_MODE = "jwt"

from drf_auth_package.conf import get_authentication_classes

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': get_authentication_classes(),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}
```

### 5. Include URLs

Add the package URLs to your project's `urls.py`:

```python
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('drf_auth_package.urls')),
    # Your other URLs...
]
```

### 6. Run Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### 7. You're Ready!

Your authentication system is now set up. See the [Endpoints](#endpoints) section below for available API endpoints.

## Configuration

### Database Configuration (PostgreSQL Example)

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRES_DB', 'mydb'),
        'USER': os.environ.get('POSTGRES_USER', 'myuser'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD', 'secret'),
        'HOST': os.environ.get('POSTGRES_HOST', 'localhost'),
        'PORT': os.environ.get('POSTGRES_PORT', '5432'),
    }
}
```

### Authentication Settings

All settings are optional with sensible defaults:

```python
# Authentication mode: "jwt", "session", or "both"
DRF_AUTH_BACKEND_MODE = "jwt"

# JWT Settings
DRF_AUTH_JWT_ACCESS_TOKEN_LIFETIME_MINUTES = 60  # 1 hour
DRF_AUTH_JWT_REFRESH_TOKEN_LIFETIME_DAYS = 7  # 7 days
DRF_AUTH_JWT_ALGORITHM = "HS256"
DRF_AUTH_JWT_SIGNING_KEY = SECRET_KEY  # Uses Django's SECRET_KEY by default

# Email Verification
DRF_AUTH_EMAIL_VERIFICATION_REQUIRED = True
DRF_AUTH_EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS = 24

# Password Reset
DRF_AUTH_PASSWORD_RESET_TOKEN_EXPIRY_HOURS = 1

# Phone Verification
DRF_AUTH_PHONE_VERIFICATION_REQUIRED = False
DRF_AUTH_PHONE_OTP_LENGTH = 6
DRF_AUTH_PHONE_OTP_EXPIRY_SECONDS = 300  # 5 minutes
DRF_AUTH_PHONE_OTP_MAX_ATTEMPTS = 3

# Social Auth - Google
DRF_AUTH_GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
DRF_AUTH_GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

# Social Auth - Facebook
DRF_AUTH_FACEBOOK_APP_ID = os.environ.get('FACEBOOK_APP_ID', '')
DRF_AUTH_FACEBOOK_APP_SECRET = os.environ.get('FACEBOOK_APP_SECRET', '')

# Social Auth - Twitter
DRF_AUTH_TWITTER_API_KEY = os.environ.get('TWITTER_API_KEY', '')
DRF_AUTH_TWITTER_API_SECRET = os.environ.get('TWITTER_API_SECRET', '')
```

### Environment Variables

Create a `.env` file for sensitive credentials:

```bash
# Django
SECRET_KEY=your-secret-key-here
DEBUG=True

# Database
POSTGRES_DB=mydb
POSTGRES_USER=myuser
POSTGRES_PASSWORD=secret
POSTGRES_HOST=localhost
POSTGRES_PORT=5432

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Facebook OAuth
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret

# Twitter OAuth
TWITTER_API_KEY=your-twitter-api-key
TWITTER_API_SECRET=your-twitter-api-secret
```

## Endpoints

All endpoints are prefixed with `/api/auth/` (assuming you included URLs at `/api/`).

### User Registration & Basic Auth

#### Register

**POST** `/api/auth/register/`

Request:
```json
{
    "email": "user@example.com",
    "password": "SecurePass123",
    "password_confirm": "SecurePass123",
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "+1234567890"
}
```

Response (JWT mode):
```json
{
    "user": {
        "id": "uuid-here",
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "phone_number": "+1234567890",
        "email_verified": false,
        "phone_verified": false,
        "is_active": true,
        "date_joined": "2024-01-01T00:00:00Z"
    },
    "tokens": {
        "access": "eyJ0eXAiOiJKV1QiLCJh...",
        "refresh": "eyJ0eXAiOiJKV1QiLCJh..."
    },
    "message": "User registered successfully. Please verify your email."
}
```

#### Login

**POST** `/api/auth/login/`

Request:
```json
{
    "email": "user@example.com",
    "password": "SecurePass123"
}
```

Response (JWT mode):
```json
{
    "user": {
        "id": "uuid-here",
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "email_verified": true,
        "phone_verified": false
    },
    "tokens": {
        "access": "eyJ0eXAiOiJKV1QiLCJh...",
        "refresh": "eyJ0eXAiOiJKV1QiLCJh..."
    },
    "message": "Login successful."
}
```

#### Logout

**POST** `/api/auth/logout/`

Headers:
```
Authorization: Bearer <access_token>
```

Response:
```json
{
    "message": "Logout successful."
}
```

#### Get Current User

**GET** `/api/auth/me/`

Headers:
```
Authorization: Bearer <access_token>
```

Response:
```json
{
    "user": {
        "id": "uuid-here",
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "phone_number": "+1234567890",
        "email_verified": true,
        "phone_verified": true
    }
}
```

### Password Management

#### Change Password

**POST** `/api/auth/password/change/`

Headers:
```
Authorization: Bearer <access_token>
```

Request:
```json
{
    "old_password": "OldPass123",
    "new_password": "NewSecurePass123",
    "new_password_confirm": "NewSecurePass123"
}
```

Response:
```json
{
    "message": "Password changed successfully. Please log in again."
}
```

#### Request Password Reset

**POST** `/api/auth/password/reset/`

Request:
```json
{
    "email": "user@example.com"
}
```

Response:
```json
{
    "message": "If an account with that email exists, a password reset link has been sent."
}
```

#### Confirm Password Reset

**POST** `/api/auth/password/reset/confirm/`

Request:
```json
{
    "token": "reset-token-here",
    "new_password": "NewSecurePass123",
    "new_password_confirm": "NewSecurePass123"
}
```

Response:
```json
{
    "message": "Password reset successfully. Please log in with your new password."
}
```

### Email Verification

#### Verify Email

**POST** `/api/auth/email/verify/`

Request:
```json
{
    "token": "verification-token-here"
}
```

Response:
```json
{
    "message": "Email verified successfully."
}
```

#### Resend Verification Email

**POST** `/api/auth/email/verify/resend/`

Headers:
```
Authorization: Bearer <access_token>
```

Response:
```json
{
    "message": "Verification email sent."
}
```

### Phone Authentication

#### Request OTP

**POST** `/api/auth/phone/request-otp/`

Request:
```json
{
    "phone_number": "+1234567890"
}
```

Response:
```json
{
    "message": "OTP sent successfully. [DEV MODE: OTP is 123456]"
}
```

#### Verify OTP

**POST** `/api/auth/phone/verify-otp/`

Request:
```json
{
    "phone_number": "+1234567890",
    "otp": "123456"
}
```

Response:
```json
{
    "message": "Phone number verified successfully."
}
```

#### Login with Phone

**POST** `/api/auth/phone/login/`

Request:
```json
{
    "phone_number": "+1234567890",
    "otp": "123456"
}
```

Response (JWT mode):
```json
{
    "user": {
        "id": "uuid-here",
        "email": "user@example.com",
        "phone_number": "+1234567890",
        "phone_verified": true
    },
    "tokens": {
        "access": "eyJ0eXAiOiJKV1QiLCJh...",
        "refresh": "eyJ0eXAiOiJKV1QiLCJh..."
    },
    "message": "Login successful."
}
```

### Social Authentication

#### Google Login

**POST** `/api/auth/social/google/`

Request:
```json
{
    "token": "google-id-token-here"
}
```

Response (JWT mode):
```json
{
    "user": {
        "id": "uuid-here",
        "email": "user@gmail.com",
        "first_name": "John",
        "last_name": "Doe",
        "email_verified": true
    },
    "tokens": {
        "access": "eyJ0eXAiOiJKV1QiLCJh...",
        "refresh": "eyJ0eXAiOiJKV1QiLCJh..."
    },
    "message": "User logged in successfully via Google"
}
```

#### Facebook Login

**POST** `/api/auth/social/facebook/`

Request:
```json
{
    "token": "facebook-access-token-here"
}
```

Response: Similar to Google login response.

#### Twitter Login

**POST** `/api/auth/social/twitter/`

Request:
```json
{
    "oauth_token": "twitter-oauth-token",
    "oauth_token_secret": "twitter-oauth-token-secret"
}
```

Response: Similar to Google login response.

### JWT Token Management

#### Obtain Token Pair

**POST** `/api/auth/jwt/token/`

Request:
```json
{
    "email": "user@example.com",
    "password": "SecurePass123"
}
```

Response:
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJh...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJh..."
}
```

#### Refresh Access Token

**POST** `/api/auth/jwt/token/refresh/`

Request:
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJh..."
}
```

Response:
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJh..."
}
```

#### Verify Token

**POST** `/api/auth/jwt/token/verify/`

Request:
```json
{
    "token": "eyJ0eXAiOiJKV1QiLCJh..."
}
```

Response:
```json
{
    "valid": true,
    "payload": {
        "user_id": "uuid-here",
        "email": "user@example.com",
        "exp": 1234567890,
        "iat": 1234567890,
        "type": "access"
    }
}
```

## Security

### Best Practices

1. **Always use HTTPS** in production
2. **Configure CORS properly** using `django-cors-headers`
3. **Enable CSRF protection** for session-based auth
4. **Use secure cookies** for session authentication
5. **Rate limit authentication endpoints** using DRF throttling
6. **Keep secrets in environment variables**, not in code
7. **Regularly rotate JWT signing keys** in production

### Rate Limiting Example

```python
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    }
}
```

### CORS Configuration

```python
# Install: pip install django-cors-headers

INSTALLED_APPS = [
    # ...
    'corsheaders',
    # ...
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    # ... other middleware
]

# Development
CORS_ALLOW_ALL_ORIGINS = True

# Production
CORS_ALLOWED_ORIGINS = [
    "https://yourfrontend.com",
]
```

## Extensibility

### Override Serializers

```python
from drf_auth_package.serializers import RegisterSerializer

class CustomRegisterSerializer(RegisterSerializer):
    custom_field = serializers.CharField()

    def create(self, validated_data):
        # Custom logic
        return super().create(validated_data)
```

### Override Views

```python
from drf_auth_package.views import RegisterView

class CustomRegisterView(RegisterView):
    serializer_class = CustomRegisterSerializer

    def post(self, request):
        # Custom logic
        return super().post(request)
```

### Custom User Fields

Extend the User model:

```python
from drf_auth_package.models import User

# Create a UserProfile model
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField()
    avatar = models.ImageField()
```

### Integrate SMS Provider

Modify `drf_auth_package/services/phone_service.py`:

```python
from twilio.rest import Client

def send_otp(phone_number, otp):
    client = Client(account_sid, auth_token)
    message = client.messages.create(
        body=f"Your OTP is: {otp}",
        from_='+1234567890',
        to=phone_number
    )
    return message.sid
```

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=drf_auth_package --cov-report=html

# Run specific test
pytest tests/test_auth_flow.py
```

## Example Django Project

See the `examples/` directory for a complete Django project using this package.

```bash
cd examples/demo_project
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

## Requirements

- Python 3.10+
- Django 4.0+
- Django REST Framework 3.14+
- PostgreSQL (recommended)
- PyJWT 2.8.0+

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/drf-auth-package/issues
- Documentation: See this README

## Changelog

### Version 1.0.0 (2024-01-01)

- Initial release
- Email/password authentication
- Phone OTP authentication
- Social logins (Google, Facebook, Twitter)
- JWT and session-based auth
- Email and phone verification
- Password reset functionality
- Production-ready with logging and security features
