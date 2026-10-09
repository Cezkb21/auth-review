package rest

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"pawsy/internal/auth/app"
	"pawsy/internal/auth/domain"
	"pawsy/internal/auth/mocks"
	"pawsy/internal/auth/testutils"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	testTTLDays             = 30
	testTimeContextInSecond = 5
)

type testDeps struct {
	userRepo     *mocks.MockUserRepo
	userCache    *mocks.MockUserCache
	tokenRepo    *mocks.MockTokenRepo
	passHasher   *mocks.MockHasher
	tokenHasher  *mocks.MockHasher
	tokenManager *mocks.MockTokenManager
	service      *app.AuthService

	handler *AuthHandler
}

func setupTest(t *testing.T) *testDeps {

	mockUserRepo := new(mocks.MockUserRepo)
	mockUserCache := new(mocks.MockUserCache)
	mockTokenRepo := new(mocks.MockTokenRepo)
	mockPassHasher := new(mocks.MockHasher)
	mockTokenHasher := new(mocks.MockHasher)
	mockTokenManager := new(mocks.MockTokenManager)
	logger := slog.Default()

	svc := app.NewAuthService(
		mockUserRepo,
		mockUserCache,
		mockTokenRepo,
		mockPassHasher,
		mockTokenHasher,
		mockTokenManager,
		logger,
	)
	hlr := NewAuthHandler(svc, testTTLDays, testTimeContextInSecond, logger)

	t.Cleanup(func() {
		mockUserRepo.AssertExpectations(t)
		mockUserCache.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
		mockPassHasher.AssertExpectations(t)
		mockTokenHasher.AssertExpectations(t)
		mockTokenManager.AssertExpectations(t)
	})

	return &testDeps{
		userRepo:     mockUserRepo,
		userCache:    mockUserCache,
		tokenRepo:    mockTokenRepo,
		passHasher:   mockPassHasher,
		tokenHasher:  mockTokenHasher,
		tokenManager: mockTokenManager,
		service:      svc,
		handler:      hlr,
	}
}
func TestAuthHandler_HandleLogin(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMocks     func(*testDeps)
		expectedStatus int
		expectedBody   map[string]interface{}
		expectedCookie *http.Cookie
	}{
		{
			name: "Success",
			requestBody: LoginRequest{
				Email:    testutils.TestEmail,
				Password: testutils.TestPassword,
			},
			setupMocks: func(deps *testDeps) {
				deps.userCache.On("FindByEmail", mock.Anything, testutils.TestEmail).Return(nil, domain.ErrUserNotFound)
				deps.userRepo.On("FindByEmail", mock.Anything, testutils.TestEmail).Return(&domain.User{
					ID:             testutils.TestUserID,
					Email:          testutils.TestEmail,
					HashedPassword: testutils.TestHashedPassword,
					Role:           testutils.TestRole,
				}, nil)
				deps.userCache.On("Create", mock.Anything, mock.Anything).Return(nil)
				deps.passHasher.On("Verify", testutils.TestPassword, testutils.TestHashedPassword).Return(true, nil)
				deps.tokenManager.On("GenerateAccessToken", testutils.TestUserID, testutils.TestRole).Return(testutils.TestAccessToken, nil)
				deps.tokenManager.On("GenerateRefreshToken", testutils.TestUserID).Return(testutils.TestRefreshToken, time.Now().Add(time.Hour), nil)
				deps.tokenHasher.On("Hash", testutils.TestRefreshToken).Return(testutils.TestHashedRefreshToken, nil)
				deps.tokenRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.RefreshTokenModel")).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"accessToken": testutils.TestAccessToken,
				"user": map[string]interface{}{
					"userId": testutils.TestUserID,
					"email":  testutils.TestEmail,
				},
			},
			expectedCookie: &http.Cookie{
				Name:     "refreshToken",
				Value:    testutils.TestRefreshToken,
				Path:     "/api/refresh",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   30 * 24 * 3600,
			},
		},
		{
			name:           "Invalid JSON body",
			requestBody:    "invalid json",
			setupMocks:     func(deps *testDeps) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   nil,
			expectedCookie: nil,
		},
		{
			name: "Missing email or password",
			requestBody: LoginRequest{
				Email:    "",
				Password: "",
			},
			setupMocks:     func(deps *testDeps) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   nil,
			expectedCookie: nil,
		},
		{
			name: "User not found",
			requestBody: LoginRequest{
				Email:    testutils.TestEmail,
				Password: "wrong",
			},
			setupMocks: func(deps *testDeps) {
				deps.userCache.On("FindByEmail", mock.Anything, testutils.TestEmail).Return(nil, domain.ErrUserNotFound)
				deps.userRepo.On("FindByEmail", mock.Anything, testutils.TestEmail).Return(nil, domain.ErrUserNotFound)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   nil,
			expectedCookie: nil,
		},
		{
			name: "Wrong password",
			requestBody: LoginRequest{
				Email:    testutils.TestEmail,
				Password: "wrong",
			},
			setupMocks: func(deps *testDeps) {
				deps.userCache.On("FindByEmail", mock.Anything, testutils.TestEmail).Return(nil, domain.ErrUserNotFound)
				deps.userRepo.On("FindByEmail", mock.Anything, testutils.TestEmail).Return(&domain.User{
					ID:             testutils.TestUserID,
					Email:          testutils.TestEmail,
					HashedPassword: testutils.TestHashedPassword,
					Role:           testutils.TestRole,
				}, nil)
				deps.userCache.On("Create", mock.Anything, mock.Anything).Return(nil)
				deps.passHasher.On("Verify", "wrong", testutils.TestHashedPassword).Return(false, nil)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   nil,
			expectedCookie: nil,
		},
		{
			name: "Internal server error (DB error)",
			requestBody: LoginRequest{
				Email:    testutils.TestEmail,
				Password: testutils.TestPassword,
			},
			setupMocks: func(deps *testDeps) {
				deps.userCache.On("FindByEmail", mock.Anything, testutils.TestEmail).Return(nil, domain.ErrUserNotFound)
				deps.userRepo.On("FindByEmail", mock.Anything, testutils.TestEmail).Return(nil, errors.New("db connection lost"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   nil,
			expectedCookie: nil,
		},
		{
			name: "Internal server error (token generation error)",
			requestBody: LoginRequest{
				Email:    testutils.TestEmail,
				Password: testutils.TestPassword,
			},
			setupMocks: func(deps *testDeps) {
				deps.userCache.On("FindByEmail", mock.Anything, testutils.TestEmail).Return(nil, domain.ErrUserNotFound)
				deps.userRepo.On("FindByEmail", mock.Anything, testutils.TestEmail).Return(&domain.User{
					ID:             testutils.TestUserID,
					Email:          testutils.TestEmail,
					HashedPassword: testutils.TestHashedPassword,
					Role:           testutils.TestRole,
				}, nil)
				deps.userCache.On("Create", mock.Anything, mock.Anything).Return(nil)
				deps.passHasher.On("Verify", testutils.TestPassword, testutils.TestHashedPassword).Return(true, nil)
				deps.tokenManager.On("GenerateAccessToken", testutils.TestUserID, testutils.TestRole).Return("", errors.New("jwt signing failed"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   nil,
			expectedCookie: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := setupTest(t)
			tt.setupMocks(deps)

			handler := deps.handler

			var bodyBytes []byte
			var err error
			switch v := tt.requestBody.(type) {
			case string:
				bodyBytes = []byte(v)
			default:
				bodyBytes, err = json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("failed to marshal request body: %v", err)
				}
			}

			req := httptest.NewRequest("POST", "/login", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			handler.HandleLogin(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedBody != nil {
				var resp map[string]interface{}
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, resp)
			}

			if tt.expectedCookie != nil {
				cookies := w.Result().Cookies()
				assert.Len(t, cookies, 1)
				cookie := cookies[0]
				assert.Equal(t, tt.expectedCookie.Name, cookie.Name)
				assert.Equal(t, tt.expectedCookie.Value, cookie.Value)
				assert.Equal(t, tt.expectedCookie.Path, cookie.Path)
				assert.Equal(t, tt.expectedCookie.HttpOnly, cookie.HttpOnly)
				assert.Equal(t, tt.expectedCookie.Secure, cookie.Secure)
				assert.Equal(t, tt.expectedCookie.SameSite, cookie.SameSite)
				assert.Equal(t, tt.expectedCookie.MaxAge, cookie.MaxAge)
			} else {
				cookies := w.Result().Cookies()
				assert.Empty(t, cookies)
			}
		})
	}
}
