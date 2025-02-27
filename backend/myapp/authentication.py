from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth.models import AnonymousUser

class JWTAuthenticationFromCookie(BaseAuthentication):
    def authenticate(self, request):
        access_token = request.COOKIES.get("access_token")

        if not access_token:
            return None  

        try:
            token = AccessToken(access_token)
            user = token.user
            return (user, token)
        except Exception:
            raise AuthenticationFailed("Invalid or expired token")

    def authenticate_header(self, request):
        return "Bearer"
