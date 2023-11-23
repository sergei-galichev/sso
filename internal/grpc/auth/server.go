package authgrpc

import (
	"context"
	"errors"
	ssov1 "github.com/sergei-galichev/protos/gen/go/sso"
	"go-auth-service/sso/internal/services/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int,
	) (token string, err error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
	) (userID int64, err error)
	IsAdmin(
		ctx context.Context,
		userID int64,
	) (bool, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPCServer *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPCServer, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(
	ctx context.Context,
	request *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	if err := validateLogin(request); err != nil {
		return nil, err
	}
	token, err := s.auth.Login(ctx, request.GetEmail(), request.GetPassword(), int(request.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	request *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(request); err != nil {
		return nil, err
	}
	uid, err := s.auth.RegisterNewUser(ctx, request.GetEmail(), request.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "failed to register user")
	}

	return &ssov1.RegisterResponse{
		UserId: uid,
	}, nil
}

func (s *serverAPI) IsAdmin(
	ctx context.Context,
	request *ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(request); err != nil {
		return nil, err
	}
	isAdmin, err := s.auth.IsAdmin(ctx, request.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to check admin status")
	}
	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

//Private methods

func validateLogin(request *ssov1.LoginRequest) error {
	if request.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if request.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	if request.GetAppId() == 0 {
		return status.Error(codes.InvalidArgument, "app_id is required")
	}
	return nil
}

func validateRegister(request *ssov1.RegisterRequest) error {
	if request.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if request.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	return nil
}

func validateIsAdmin(request *ssov1.IsAdminRequest) error {
	if request.GetUserId() == 0 {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}
	return nil
}
