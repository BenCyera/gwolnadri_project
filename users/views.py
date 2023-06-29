import os
import requests
from rest_framework import status, permissions, generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework.generics import get_object_or_404
from django.shortcuts import redirect, get_object_or_404

from django.http import JsonResponse
from json.decoder import JSONDecodeError
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.providers.google import views as google_view
from allauth.socialaccount.providers.kakao import views as kakao_view
from allauth.socialaccount.providers.naver import views as naver_view
from allauth.socialaccount.models import SocialAccount
from .models import User
from .serializers import (
    UserTokenObtainPairSerializer,
    UserSerializer,
    UserProfileSerializer,
    UpdateUserSerializer,
    ChangePasswordSerializer,
)


# 회원가입
class SignupView(APIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

    def post(self, request):
        email = request.data.get("email", "")
        if User.objects.filter(email=email).exists():
            return Response(
                {"email": "이미 가입된 이메일입니다."}, status=status.HTTP_400_BAD_REQUEST
            )
        username = request.data.get("username", "")
        if User.objects.filter(username=username).exists():
            return Response(
                {"username": "이미 존재하는 유저네임입니다."}, status=status.HTTP_400_BAD_REQUEST
            )
        password = request.data.get("password", "")
        password2 = request.data.get("password2", "")
        if password != password2:
            return Response(
                {"password2": "비밀번호가 불일치합니다."}, status=status.HTTP_400_BAD_REQUEST
            )
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "가입완료!"}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_403_FORBIDDEN)


# 로그인
class LoginView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = UserTokenObtainPairSerializer


class CustomRefreshToken(RefreshToken):
    @classmethod
    def for_user(cls, user):
        token = super().for_user(user)
        token["email"] = user.email
        return token


def generate_jwt_token(user):
    refresh = CustomRefreshToken.for_user(user)
    return {"refresh": str(refresh), "access": str(refresh.access_token)}


# 마이페이지 보기
class Me(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        if user:
            serializer = UserProfileSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)


# 회원정보 수정하기, 탈퇴하기
class UpdateProfileView(generics.UpdateAPIView):
    def get_serializer_class(self):
        if self.request.data.get("password"):
            return ChangePasswordSerializer
        return UpdateUserSerializer

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"message": "회원 탈퇴 완료"}, status=status.HTTP_204_NO_CONTENT)


# 비밀번호 변경
class ChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangePasswordSerializer


# # 소셜로그인
# BASE_URL = "http://127.0.0.1:8000/"
# GOOGLE_CALLBACK_URI = BASE_URL + "users/google/login/callback/"
# KAKAO_CALLBACK_URI = BASE_URL + "users/kakao/login/callback/"
# NAVER_CALLBACK_URI = BASE_URL + "users/naver/login/callback/"

# state = os.environ.get("STATE")


# ################## GOOGLE Login ##################
# def google_login(request):
#     # Code Request
#     scope = "https://www.googleapis.com/auth/userinfo.email"
#     client_id = os.environ.get("SOCIAL_AUTH_GOOGLE_CLIENT_ID")
#     return redirect(
#         f"https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&response_type=code&redirect_uri={GOOGLE_CALLBACK_URI}&scope={scope}"
#     )


# def google_callback(request):
#     client_id = os.environ.get("SOCIAL_AUTH_GOOGLE_CLIENT_ID")
#     client_secret = os.environ.get("SOCIAL_AUTH_GOOGLE_SECRET")
#     code = request.GET.get("code")

#     ## 받은 코드로 Access Token Request
#     token_req = requests.post(
#         f"https://oauth2.googleapis.com/token?client_id={client_id}&client_secret={client_secret}&code={code}&grant_type=authorization_code&redirect_uri={GOOGLE_CALLBACK_URI}&state={state}"
#     )

#     # json으로 변환
#     token_req_json = token_req.json()
#     error = token_req_json.get("error")

#     # 에러
#     if error is not None:
#         raise JSONDecodeError(error)

#     # 에러 아니면, get access_token
#     access_token = token_req_json.get("access_token")

#     ## 받은 access_token으로 Email Request
#     email_req = requests.get(
#         f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={access_token}"
#     )
#     email_req_status = email_req.status_code

#     # 에러
#     if email_req_status != 200:
#         return JsonResponse(
#             {"err_msg": "FAILED TO GET EMAIL"}, status=status.HTTP_400_BAD_REQUEST
#         )

#     # 에러 아니면, get email
#     email_req_json = email_req.json()
#     email = email_req_json.get("email")

#     ## 회원가입/ 로그인
#     try:
#         user = User.objects.get(email=email)
#         social_user = SocialAccount.objects.get(user=user)

#         # 소셜 유저 아닐 경우
#         if social_user is None:
#             return JsonResponse(
#                 {"err_msg": "EMAIL EXISTS BUT NOT SOCIAL USER"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         # 소셜 유저지만 Google이 아닐 경우
#         if social_user.provider != "google":
#             return JsonResponse(
#                 {"err_msg": "NO MATCHING SOCIAL TYPE"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         # 기존에 Google로 가입된 유저 - 로그인, jwt 발급
#         data = {"access_token": access_token, "code": code}
#         accept = requests.post(f"{BASE_URL}users/google/login/finish/", data=data)
#         accept_status = accept.status_code

#         # 에러 - 로그인 실패
#         if accept_status != 200:
#             return JsonResponse({"err_msg": "FAILED TO SIGN IN"}, status=accept_status)

#         accept_json = accept.json()
#         accept_json.pop("user", None)
#         return JsonResponse(accept_json)

#     # 기존 가입된 유저가 없으면, 새로 회원가입
#     except User.DoesNotExist:
#         data = {"access_token": access_token, "code": code}
#         accept = requests.post(f"{BASE_URL}users/google/login/finish/", data=data)
#         accept_status = accept.status_code

#         # 에러 - 회원가입 실패
#         if accept_status != 200:
#             return JsonResponse({"err_msg": "FAILED TO SIGNUP"}, status=accept_status)

#         accept_json = accept.json()
#         accept_json.pop("user", None)
#         return JsonResponse(accept_json)


# class GoogleLogin(SocialLoginView):
#     adapter_class = google_view.GoogleOAuth2Adapter
#     callback_url = GOOGLE_CALLBACK_URI
#     client_class = OAuth2Client


# ################## KAKAO Login ##################
# def kakao_login(request):
#     # Code Request
#     rest_api_key = os.environ.get("KAKAO_REST_API_KEY")
#     return redirect(
#         f"https://kauth.kakao.com/oauth/authorize?client_id={rest_api_key}&redirect_uri={KAKAO_CALLBACK_URI}&response_type=code"
#     )


# def kakao_callback(request):
#     rest_api_key = os.environ.get("KAKAO_REST_API_KEY")
#     code = request.GET.get("code")
#     redirect_uri = KAKAO_CALLBACK_URI

#     ## 받은 코드로 Access Token Request
#     token_req = requests.get(
#         f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={rest_api_key}&redirect_uri={redirect_uri}&code={code}"
#     )

#     # json으로 변환
#     token_req_json = token_req.json()
#     error = token_req_json.get("error", None)

#     # 에러
#     if error is not None:
#         raise JSONDecodeError(error)

#     # 에러 아니면, get access_token
#     access_token = token_req_json.get("access_token")

#     ## 받은 access_token으로 Profile Request
#     profile_request = requests.get(
#         "https://kapi.kakao.com/v2/user/me",
#         headers={"Authorization": f"Bearer {access_token}"},
#     )
#     profile_json = profile_request.json()
#     error = profile_json.get("error")
#     if error is not None:
#         raise JSONDecodeError(error)

#     kakao_account = profile_json.get("kakao_account")
#     email = kakao_account.get("email")

#     ## 회원가입/ 로그인
#     try:
#         user = User.objects.get(email=email)
#         social_user = SocialAccount.objects.get(user=user)

#         # 소셜 유저가 아닐 경우
#         if social_user is None:
#             return JsonResponse(
#                 {"err_msg": "EMAIL EXISTS BUT NOT SOCIAL USER"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         # 소셜 유저지만 Kakao가 아닐 경우
#         if social_user.provider != "kakao":
#             return JsonResponse(
#                 {"err_msg": "NO MATCHING SOCIAL TYPE"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         # 기존에 Kakao로 가입된 유저 - 로그인
#         data = {"access_token": access_token, "code": code}
#         accept = requests.post(f"{BASE_URL}users/kakao/login/finish/", data=data)
#         accept_status = accept.status_code

#         # 에러 - 로그인 실패
#         if accept_status != 200:
#             return JsonResponse({"err_msg": "FAILED TO SIGN IN"}, status=accept_status)

#         accept_json = accept.json()
#         accept_json.pop("user", None)
#         return JsonResponse(accept_json)

#         # JWT 토큰 발급 후 redirect
#         jwt_token = generate_jwt_token(user)
#         response = HttpResponseRedirect(f"{BASE_URL}")
#         response.set_cookie("jwt_token", jwt_token)
#         return response

#     # 기존 가입된 유저가 없으면, 새로 회원가입
#     except User.DoesNotExist:
#         data = {"access_token": access_token, "code": code}
#         accept = requests.post(f"{BASE_URL}users/kakao/login/finish/", data=data)
#         accept_status = accept.status_code

#         # 에러 - 회원가입 실패
#         if accept_status != 200:
#             return JsonResponse({"err_msg": "FAILED TO SIGN UP"}, status=accept_status)

#         accept_json = accept.json()
#         accept_json.pop("user", None)
#         return JsonResponse(accept_json)


# class KakaoLogin(SocialLoginView):
#     adapter_class = kakao_view.KakaoOAuth2Adapter
#     client_class = OAuth2Client
#     callback_url = KAKAO_CALLBACK_URI


# ################## NAVER Login ##################
# def naver_login(request):
#     # Code Request
#     client_id = os.environ.get("SOCIAL_AUTH_NAVER_CLIENT_ID")
#     return redirect(
#         f"https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id={client_id}&state=STATE_STRING&redirect_uri={NAVER_CALLBACK_URI}"
#     )


# def naver_callback(request):
#     client_id = os.environ.get("SOCIAL_AUTH_NAVER_CLIENT_ID")
#     client_secret = os.environ.get("SOCIAL_AUTH_NAVER_SECRET")
#     code = request.GET.get("code")
#     state_string = request.GET.get("state")

#     ## 받은 코드로 Access Token Request
#     token_request = requests.get(
#         f"https://nid.naver.com/oauth2.0/token?grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&state={state_string}"
#     )

#     # json으로 변환
#     token_response_json = token_request.json()
#     error = token_response_json.get("error", None)

#     # 에러
#     if error is not None:
#         raise JSONDecodeError(error)

#     # 에러 아니면, get access_token
#     access_token = token_response_json.get("access_token")

#     ## 받은 access_token으로 Profile Request
#     profile_req = requests.post(
#         "https://openapi.naver.com/v1/nid/me",
#         headers={"Authorization": f"Bearer {access_token}"},
#     )
#     profile_json = profile_req.json()
#     email = profile_json.get("response").get("email")

#     # 에러
#     if email is None:
#         raise JSONDecodeError(error)

#     ## Email, access_token, code 으로 회원가입/ 로그인
#     try:
#         user = User.objects.get(email=email)
#         social_user = SocialAccount.objects.get(user=user)

#         # 소셜 유저 아닐 경우
#         if social_user is None:
#             return JsonResponse(
#                 {"err_msg": "EMAIL EXISTS BUT NOT SOCIAL USER"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         # 소셜 유저지만 Naver이 아닐 경우
#         if social_user.provider != "naver":
#             return JsonResponse(
#                 {"err_msg": "NO MATCHING SOCIAL TYPE"},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         # 기존에 Naver로 가입된 유저 - 로그인
#         data = {"access_token": access_token, "code": code}
#         accept = requests.post(f"{BASE_URL}users/naver/login/finish/", data=data)
#         accept_status = accept.status_code

#         if accept_status != 200:
#             return JsonResponse({"err_msg": "FAILED TO SIGN IN"}, status=accept_status)

#         accept_json = accept.json()
#         accept_json.pop("user", None)
#         return JsonResponse(accept_json)

#     # 기존 가입된 유저가 없으면, 새로 회원가입
#     except User.DoesNotExist:
#         data = {"access_token": access_token, "code": code}
#         accept = requests.post(f"{BASE_URL}users/naver/login/finish/", data=data)
#         accept_status = accept.status_code

#         if accept_status != 200:
#             return JsonResponse({"err_msg": "FAILED TO SIGN UP"}, status=accept_status)

#         accept_json = accept.json()
#         accept_json.pop("user", None)
#         return JsonResponse(accept_json)


# class NaverLogin(SocialLoginView):
#     adapter_class = naver_view.NaverOAuth2Adapter
#     callback_url = NAVER_CALLBACK_URI
#     client_class = OAuth2Client
