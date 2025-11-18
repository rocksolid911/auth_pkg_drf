# Demo Project - DRF Auth Package

This is a complete example Django project demonstrating how to use the DRF Auth Package.

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install DRF Auth Package

From the root of the repository:

```bash
cd ../..
pip install -e .
cd examples/demo_project
```

### 3. Configure Environment

Copy the example environment file and update it with your settings:

```bash
cp .env.example .env
```

Edit `.env` with your database credentials and API keys.

### 4. Set Up Database

Make sure PostgreSQL is running, then:

```bash
python manage.py migrate
```

### 5. Create Superuser (Optional)

```bash
python manage.py createsuperuser
```

### 6. Run Development Server

```bash
python manage.py runserver
```

The API will be available at `http://localhost:8000/api/`

## Available Endpoints

- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login
- `POST /api/auth/logout/` - User logout
- `GET /api/auth/me/` - Get current user
- `POST /api/auth/password/change/` - Change password
- `POST /api/auth/password/reset/` - Request password reset
- `POST /api/auth/password/reset/confirm/` - Confirm password reset
- `POST /api/auth/email/verify/` - Verify email
- `POST /api/auth/email/verify/resend/` - Resend verification email
- `POST /api/auth/phone/request-otp/` - Request phone OTP
- `POST /api/auth/phone/verify-otp/` - Verify phone OTP
- `POST /api/auth/phone/login/` - Login with phone
- `POST /api/auth/social/google/` - Google OAuth login
- `POST /api/auth/social/facebook/` - Facebook OAuth login
- `POST /api/auth/social/twitter/` - Twitter OAuth login
- `POST /api/auth/jwt/token/` - Obtain JWT token pair
- `POST /api/auth/jwt/token/refresh/` - Refresh access token
- `POST /api/auth/jwt/token/verify/` - Verify token

## Testing the API

### Using cURL

#### Register a new user:
```bash
curl -X POST http://localhost:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123",
    "password_confirm": "TestPass123",
    "first_name": "Test",
    "last_name": "User"
  }'
```

#### Login:
```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123"
  }'
```

#### Get current user (with token):
```bash
curl -X GET http://localhost:8000/api/auth/me/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Using Python Requests

```python
import requests

# Register
response = requests.post('http://localhost:8000/api/auth/register/', json={
    'email': 'test@example.com',
    'password': 'TestPass123',
    'password_confirm': 'TestPass123',
    'first_name': 'Test',
    'last_name': 'User'
})
print(response.json())

# Login
response = requests.post('http://localhost:8000/api/auth/login/', json={
    'email': 'test@example.com',
    'password': 'TestPass123'
})
tokens = response.json()['tokens']
access_token = tokens['access']

# Get user info
response = requests.get('http://localhost:8000/api/auth/me/',
    headers={'Authorization': f'Bearer {access_token}'}
)
print(response.json())
```

## Switching Authentication Modes

Edit `.env` and change `DRF_AUTH_BACKEND_MODE`:

- `jwt` - JWT-based authentication (default)
- `session` - Session-based authentication
- `both` - Support both JWT and session authentication

## Admin Panel

Access the Django admin at `http://localhost:8000/admin/` with your superuser credentials.

## Troubleshooting

### Database Connection Issues

Make sure PostgreSQL is running and the credentials in `.env` are correct.

### Import Errors

Make sure you've installed the DRF Auth Package from the repository root:
```bash
pip install -e ../..
```

### Token Issues

If tokens aren't working, check that:
1. `DRF_AUTH_BACKEND_MODE` is set correctly
2. The `Authorization` header format is `Bearer <token>`
3. The token hasn't expired
