import os
import requests
import random, string
from django.http import HttpResponse
from django.http import JsonResponse
from json.decoder import JSONDecodeError
from rest_framework import status, permissions, generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework.decorators import api_view
from rest_framework.generics import get_object_or_404
from django.shortcuts import redirect, get_object_or_404

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
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "가입완료!"}, status=status.HTTP_201_CREATED)
        else:
            return Response(
                {"message": f"${serializer.errors}"}, status=status.HTTP_400_BAD_REQUEST
            )


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


# 소셜로그인
BASE_URL = os.environ.get("BASE_URL")


################## GOOGLE Login ##################
GOOGLE_CALLBACK_URI = BASE_URL + "users/google/login/callback/"
GOOGLE_REDIRECT_URI = "http://127.0.0.1:5500/assets/doc/" + "google.html"

@api_view(["POST", "GET"])
def google_login(request):
    scope = "https://www.googleapis.com/auth/userinfo.email"
    client_id = os.environ.get("SOCIAL_AUTH_GOOGLE_CLIENT_ID")
    return redirect(
        f"https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&response_type=code&redirect_uri={GOOGLE_REDIRECT_URI}&scope={scope}"
    )
    # return redirect(
    #     f"https://accounts.google.com/o/oauth2/v2/auth?client_id={client_id}&redirect_uri={GOOGLE_REDIRECT_URI}&response_type=code&scope=email%20profile"
    # )


@api_view(["POST", "GET"])
def google_callback(request):
    client_id = os.environ.get("SOCIAL_AUTH_GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("SOCIAL_AUTH_GOOGLE_SECRET")
    state = os.environ.get("STATE")
    code = request.GET.get("code")
    print("@@@@@@@1번", code)

    token_request = requests.post(
        f"https://oauth2.googleapis.com/token?client_id={client_id}&client_secret={client_secret}&code={code}&grant_type=authorization_code&redirect_uri={GOOGLE_REDIRECT_URI}&state={state}"
    )

    token_request_json = token_request.json()
    error = token_request_json.get("error")
    print("2번", token_request_json)
    print("2-1번", error)

    if error is not None:
        raise JSONDecodeError(error)

    access_token = token_request_json.get("access_token")
    print("3번", access_token)

    email_request = requests.get(
        f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={access_token}"
    )
    email_request_status = email_request.status_code
    print("4번", email_request_status)

    if email_request_status != 200:
        return JsonResponse(
            {"err_msg": "구글 이메일을 가져오지 못했습니다."}, status=status.HTTP_400_BAD_REQUEST
        )

    email_request_json = email_request.json()
    email = email_request_json.get("email")
    print("5번", email)

    try:
        user = User.objects.get(email=email)
        print("6번", user)
        social_user = SocialAccount.objects.get(user=user)
        print("7번", social_user)

        if social_user.provider != "google":
            return JsonResponse(
                {"err_msg": "일치하는 구글 계정이 없습니다. 확인해 주세요."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = {"access_token": access_token, "code": code}
        print("8번", data)
        accept = requests.post(f"{BASE_URL}users/google/login/finish/", data=data)
        print("9번", accept)
        accept_status = accept.status_code
        print("10번", accept_status)

        if accept_status != 200:
            return JsonResponse({"err_msg": "구글 로그인에 실패했습니다."}, status=accept_status)

        user, created = User.objects.get_or_create(email=email)
        # refresh_token = UserTokenObtainPairSerializer.get_token(user)
        # access_token = refresh_token.access_token
        access_token = AccessToken.for_user(user)
        refresh_token = RefreshToken.for_user(user)
        

        return Response(
            {"refresh": str(refresh_token), "access": str(access_token)},
            status=status.HTTP_200_OK,
        )

    except User.DoesNotExist:
        data = {"access_token": access_token, "code": code}
        print("12번", data)
        accept = requests.post(f"{BASE_URL}users/google/login/finish/", data=data)
        print("13번", accept)
        accept_status = accept.status_code
        print("14번", accept_status)

        if accept_status != 200:
            return JsonResponse({"err_msg": "구글로 회원가입에 실패했습니다."}, status=accept_status)

        user, created = User.objects.get_or_create(email=email)
        refresh_token = UserTokenObtainPairSerializer.get_token(user)
        access_token = refresh_token.access_token
        # access_token = AccessToken.for_user(user)
        # refresh_token = RefreshToken.for_user(user)

        return Response(
            {"refresh": str(refresh_token), "access": str(access_token)},
            status=status.HTTP_201_CREATED,
        )

    except SocialAccount.DoesNotExist:
        return JsonResponse(
            {"err_msg": "구글 이메일이 있지만 소셜 사용자는 아닙니다."}, status=status.HTTP_400_BAD_REQUEST
        )


class GoogleLogin(SocialLoginView):
    adapter_class = google_view.GoogleOAuth2Adapter
    callback_url = GOOGLE_CALLBACK_URI
    client_class = OAuth2Client
    # serializer_class = UserTokenObtainPairSerializer


################## KAKAO Login ##################
KAKAO_CALLBACK_URI = BASE_URL + "users/kakao/login/callback/"
KAKAO_REDIRECT_URI = "http://127.0.0.1:5500/assets/doc/kakao.html"


# @api_view(["POST", "GET"])
# def kakao_login(request):
#     client_id = os.environ.get("KAKAO_CLIENT_ID")
#     return redirect(
#         f"https://kauth.kakao.com/oauth/authorize?client_id={client_id}&redirect_uri={KAKAO_REDIRECT_URI}&response_type=code&scope=account_email&prompt=login"
#     )

@api_view(["POST", "GET"])
def kakao_login(request):
    client_id = os.environ.get("KAKAO_CLIENT_ID")
    return redirect(
        f"https://kauth.kakao.com/oauth/authorize?client_id={client_id}&redirect_uri={KAKAO_REDIRECT_URI}&response_type=code&prompt=login"
    )



@api_view(["POST", "GET"])
def kakao_callback(request):
    client_id = os.environ.get("KAKAO_CLIENT_ID")
    code = request.GET.get("code")

    token_request = requests.get(
        f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={client_id}&redirect_uri={KAKAO_REDIRECT_URI}&code={code}"
    )

    token_request_json = token_request.json()
    error = token_request_json.get("error", None)
    if error is not None:
        raise JSONDecodeError(error)

    access_token = token_request_json.get("access_token")

    profile_request = requests.get(
        "https://kapi.kakao.com/v2/user/me",
        headers={"Authorization": f"Bearer {access_token}", "Content-type": "application/x-www-form-urlencoded;charset=utf-8"},
    )
    profile_request_json = profile_request.json()

    kakao_account = profile_request_json.get("kakao_account")
    email = kakao_account.get("email")
    # email = kakao_account.get("kakao_account")["email"]

    if email is None:
        return JsonResponse(
            {"err_msg": "카카오 이메일을 가져오지 못했습니다."}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        user = User.objects.get(email=email)
        social_user = SocialAccount.objects.get(user=user)

        if social_user.provider != "kakao":
            return JsonResponse(
                {"err_msg": "일치하는 카카오 계정이 없습니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = {"access_token": access_token, "code": code}
        accept = requests.post(f"{BASE_URL}users/kakao/login/finish/", data=data)
        accept_status = accept.status_code

        if accept_status != 200:
            return JsonResponse({"err_msg": "카카오 로그인에 실패했습니다."}, status=accept_status)

        user, created = User.objects.get_or_create(email=email)
        refresh_token = UserTokenObtainPairSerializer.get_token(user)
        access_token = refresh_token.access_token

        return Response(
            {"refresh": str(refresh_token), "access": str(access_token)},
            status=status.HTTP_200_OK,
        )

    except User.DoesNotExist:
        data = {"access_token": access_token, "code": code}
        accept = requests.post(f"{BASE_URL}users/kakao/login/finish/", data=data)
        accept_status = accept.status_code

        if accept_status != 200:
            return JsonResponse({"err_msg": "카카오로 회원가입에 실패했습니다."}, status=accept_status)

        user, created = User.objects.get_or_create(email=email)
        refresh_token = UserTokenObtainPairSerializer.get_token(user)
        access_token = refresh_token.access_token

        return Response(
            {"refresh": str(refresh_token), "access": str(access_token)},
            status=status.HTTP_201_CREATED,
        )

    except SocialAccount.DoesNotExist:
        return JsonResponse(
            {"err_msg": "카카오 이메일이 있지만 소셜 사용자는 아닙니다."},
            status=status.HTTP_400_BAD_REQUEST,
        )


class KakaoLogin(SocialLoginView):
    adapter_class = kakao_view.KakaoOAuth2Adapter
    callback_url = KAKAO_CALLBACK_URI
    client_class = OAuth2Client

################## NAVER Login ##################
NAVER_CALLBACK_URI = BASE_URL + "users/naver/login/callback/"
NAVER_REDIRECT_URI = "http://127.0.0.1:5500/assets/doc/naver.html"

@api_view(["POST", "GET"])
def naver_login(request):
    client_id = os.environ.get("SOCIAL_AUTH_NAVER_CLIENT_ID")
    state = os.environ.get("STATE")
    return redirect(
        f"https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id={client_id}&state={state}&redirect_uri={NAVER_CALLBACK_URI}"
    )
    # return redirect(
    #     f"https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id={client_id}&redirect_uri={NAVER_CALLBACK_URI}&state={state}"
    # )

@api_view(["POST", "GET"])
def naver_callback(request):
    client_id = os.environ.get("SOCIAL_AUTH_NAVER_CLIENT_ID")
    client_secret = os.environ.get("SOCIAL_AUTH_NAVER_SECRET")
    code = request.GET.get("code")
    state = os.environ.get("STATE")

    token_request = requests.get(
        f"https://nid.naver.com/oauth2.0/token?grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&state={state}&redirect_uri={NAVER_REDIRECT_URI}"
    )

    token_response_json = token_request.json()
    error = token_response_json.get("error", None)
    if error is not None:
        raise JSONDecodeError(error)
    
    access_token = token_response_json.get("access_token")

    profile_request = requests.post(
        "https://openapi.naver.com/v1/nid/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    profile_request_json = profile_request.json()
    email = profile_request_json.get("response").get("email")

    if email is None:
        return JsonResponse(
        {"err_msg": "네이버 이메일을 가져오지 못했습니다."}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        user = User.objects.get(email=email)
        social_user = SocialAccount.objects.get(user=user)

        if social_user.provider != "naver":
            return JsonResponse(
                {"err_msg": "일치하는 네이버 계정이 없습니다"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = {"access_token": access_token, "code": code}
        accept = requests.post(f"{BASE_URL}users/naver/login/finish/", data=data)
        accept_status = accept.status_code

        if accept_status != 200:
            return JsonResponse({"err_msg": "네이버 로그인이 실패했습니다."}, status=accept_status)

        user, created = User.objects.get_or_create(email=email)
        refresh_token = UserTokenObtainPairSerializer.get_token(user)
        access_token = refresh_token.access_token

        return Response(
            {"refresh": str(refresh_token), "access": str(access_token)},
            status=status.HTTP_200_OK,
        )

    except User.DoesNotExist:
        data = {"access_token": access_token, "code": code}
        accept = requests.post(f"{BASE_URL}users/naver/login/finish/", data=data)
        accept_status = accept.status_code

        if accept_status != 200:
            return JsonResponse({"err_msg": "네이버로 회원가입이 실패했습니다."}, status=accept_status)
        
        user, created = User.objects.get_or_create(email=email)
        refresh_token = UserTokenObtainPairSerializer.get_token(user)
        access_token = refresh_token.access_token
        return Response(
            {"refresh": str(refresh_token), "access": str(access_token)},
            status=status.HTTP_201_CREATED,
        )
    
    except SocialAccount.DoesNotExist:
        return JsonResponse(
            {"err_msg": "네이버 이메일이 있지만 소셜 사용자는 아닙니다."},
            status=status.HTTP_400_BAD_REQUEST,
        )

class NaverLogin(SocialLoginView):
    adapter_class = naver_view.NaverOAuth2Adapter
    callback_url = NAVER_CALLBACK_URI
    client_class = OAuth2Client