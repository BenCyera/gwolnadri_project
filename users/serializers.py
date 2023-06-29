from rest_framework import serializers
from .models import User
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.password_validation import validate_password
from stores.serializers import StoreListSerializer
from events.serializers import EventSerializer


# 회원가입
class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True, validators=[UniqueValidator(queryset=User.objects.all())]
    )

    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = [
            "pk",
            "email",
            "username",
            "password",
            "password2",
            "profile_image",
        ]

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password": "비밀번호가 불일치합니다."})
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data["username"],
            email=validated_data["email"],
        )
        user.set_password(validated_data["password"])
        user.save()
        return user


# 로그인용
class UserTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["email"] = user.email
        return token


# 마이 프로필 - 프로필 이미지, 내가 작성한 리뷰 목록, 좋아요목록, 북마크 목록
class UserProfileSerializer(serializers.ModelSerializer):
    bookmark_stores = StoreListSerializer(many=True)
    bookmark_events = EventSerializer(many=True)
    profile_image = serializers.ImageField(
        max_length=None,
        use_url=True,
        required=False,
    )

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "username",
            "profile_image",
            "bookmark_stores",
            "bookmark_events",
        )

    # event_review = serializers.SerializerMethodField()
    # hanbok_review = serializers.SerializerMethodField()

    # #게시글 목록
    # def my_hanbok_reviews(self, obj):
    #     hanbok_reviews = HanbokReview.objects.filter(user=obj)
    #     return HanbokReviewSerializer(hanbok_reviews, many=True).data
    #
    # def my_event_reviews(self, obj):
    #     event_reviews = EventReview.objects.filter(user=obj)
    #     return EventReviewSerializer(event_reviews, many=True).data


# 회원정보 수정
class UpdateUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ("email", "username", "profile_image")
        read_only_fields = ["email", "password"]
        extra_kwargs = {
            "username": {
                "required": True,
            },
        }

    def validate_email(self, value):
        user = self.context["request"].user
        if User.objects.exclude(pk=user.pk).filter(email=value).exists():
            raise serializers.ValidationError({"email": "이미 가입된 이메일입니다."})
        return value

    def validate_username(self, value):
        user = self.context["request"].user
        if User.objects.exclude(pk=user.pk).filter(username=value).exists():
            raise serializers.ValidationError({"username": "이미 사용중인 이름입니다."})
        return value

    def update(self, instance, validated_data):
        user = self.context["request"].user

        if user.pk != instance.pk:
            raise serializers.ValidationError({"authorize": "권한이 없습니다."})

        instance.email = validated_data["email"]
        instance.username = validated_data["username"]
        instance.profile_image = validated_data["profile_image"]

        instance.save()

        return instance


# 비밀번호 변경
class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ("old_password", "password", "password2")

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"password": "비밀번호가 일치하지 않습니다."})

        return attrs

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError({"old_password": "현재 비밀번호가 일치하지 않습니다."})
        return value

    def update(self, instance, validated_data):
        user = self.context["request"].user

        if user.pk != instance.pk:
            raise serializers.ValidationError({"authorize": "권한이 없습니다."})

        instance.set_password(validated_data["password"])
        instance.save()
        return instance
