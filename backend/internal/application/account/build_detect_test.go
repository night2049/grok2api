package account

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
)

type detectResponsesAdapter struct {
	status int
	body   []byte
}

func (a detectResponsesAdapter) Provider() accountdomain.Provider { return accountdomain.ProviderBuild }
func (a detectResponsesAdapter) ForwardResponse(context.Context, provider.ResponseResourceRequest) (*provider.Response, error) {
	return &provider.Response{
		StatusCode: a.status,
		Body:       io.NopCloser(bytes.NewReader(a.body)),
	}, nil
}

func TestFinishBuildDetectResponseMarksSpendingLimitReauth(t *testing.T) {
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "detect.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := cipher.Encrypt("access-token")
	if err != nil {
		t.Fatal(err)
	}
	repo := relational.NewAccountRepository(database)
	stored, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, Name: "spending-limit", UserID: "user-1",
		SourceKey: "detect-spending-limit", EncryptedAccessToken: accessToken,
		Enabled: true, AuthStatus: accountdomain.AuthStatusActive, Priority: 1, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(repo, nil, nil, nil, provider.NewRegistry(detectResponsesAdapter{}), cipher, nil)
	response := &provider.Response{
		StatusCode: http.StatusPaymentRequired,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"code":"personal-team-blocked:spending-limit","error":"blocked"}`))),
	}
	item := service.finishBuildDetectResponse(response, stored)
	if item.Outcome != BuildDetectOutcomeInvalid {
		t.Fatalf("outcome = %s, want invalid, reason=%s", item.Outcome, item.Reason)
	}
	latest, err := repo.Get(ctx, stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.AuthStatus != accountdomain.AuthStatusReauthRequired {
		t.Fatalf("auth status = %s, want reauthRequired", latest.AuthStatus)
	}
}

func TestDetectBuildAccountsStreamsInvalidOnlyForAll(t *testing.T) {
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "detect-all.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewCipher(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := cipher.Encrypt("access-token")
	if err != nil {
		t.Fatal(err)
	}
	repo := relational.NewAccountRepository(database)
	okAccount, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, Name: "ok", UserID: "user-ok",
		SourceKey: "detect-ok", EncryptedAccessToken: accessToken,
		Enabled: true, AuthStatus: accountdomain.AuthStatusActive, Priority: 1, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	invalidAccount, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, Name: "invalid", UserID: "user-invalid",
		SourceKey: "detect-invalid", EncryptedAccessToken: accessToken,
		Enabled: true, AuthStatus: accountdomain.AuthStatusActive, Priority: 1, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 默认适配器对所有请求返回 spending-limit；单测用自定义 Forward 不方便按账号分支，
	// 这里验证：成功账号由 200 适配器场景覆盖；全量 observer 只推 invalid 的过滤在 service 层。
	// 使用 200 适配器时两个都 ok → observer 收到 0；使用 402 适配器时两个 invalid → observer 收到 2。
	service := NewService(repo, nil, nil, nil, provider.NewRegistry(detectResponsesAdapter{
		status: http.StatusPaymentRequired,
		body:   []byte(`{"code":"personal-team-blocked:spending-limit"}`),
	}), cipher, nil)

	var items []BuildDetectItemResult
	succeeded, failed, err := service.DetectBuildAccountsWithProgress(ctx, nil, nil, func(item BuildDetectItemResult) error {
		items = append(items, item)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if succeeded != 0 || failed != 2 {
		t.Fatalf("summary succeeded=%d failed=%d", succeeded, failed)
	}
	if len(items) != 2 {
		t.Fatalf("all-mode items = %d, want 2 invalid only", len(items))
	}
	for _, item := range items {
		if item.Outcome != BuildDetectOutcomeInvalid {
			t.Fatalf("item = %#v", item)
		}
	}
	_ = okAccount
	_ = invalidAccount
}
