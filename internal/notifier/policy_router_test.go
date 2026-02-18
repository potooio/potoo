package notifier

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/types"
)

func makePolicy(name string, webhookURL string, minSev string, detailLevel string) v1alpha1.NotificationPolicy {
	p := v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.NotificationPolicySpec{
			DeveloperScope: v1alpha1.NotificationScope{
				MaxDetailLevel: detailLevel,
			},
		},
	}
	if webhookURL != "" {
		p.Spec.Channels.Webhook = &v1alpha1.WebhookConfig{
			Enabled:     true,
			URL:         webhookURL,
			MinSeverity: minSev,
		}
	}
	return p
}

// webhookSenderURL extracts the URL from the first sender (assumes WebhookSender).
func webhookSenderURL(t *testing.T, senders []Sender) string {
	t.Helper()
	require.NotEmpty(t, senders)
	ws, ok := senders[0].(*WebhookSender)
	require.True(t, ok, "expected *WebhookSender")
	return ws.url
}

func TestNewPolicyRouter(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	require.NotNil(t, pr)
	assert.Empty(t, pr.Policies())
	assert.Nil(t, pr.SendersForPolicies())
}

func TestPolicyRouter_Update_CreatesSenders(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr.SetContext(ctx)

	policies := []v1alpha1.NotificationPolicy{
		makePolicy("alpha", "http://example.com/hook", "Warning", "summary"),
	}

	pr.Update(policies, nil)

	assert.Len(t, pr.Policies(), 1)
	senders := pr.SendersForPolicies()
	assert.Len(t, senders, 1)
	assert.Equal(t, "webhook", senders[0].Name())
}

func TestPolicyRouter_Update_SortsAlphabetically(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr.SetContext(ctx)

	policies := []v1alpha1.NotificationPolicy{
		makePolicy("charlie", "http://c.example.com/hook", "Warning", "summary"),
		makePolicy("alpha", "http://a.example.com/hook", "Warning", "summary"),
		makePolicy("bravo", "http://b.example.com/hook", "Warning", "summary"),
	}

	pr.Update(policies, nil)

	result := pr.Policies()
	require.Len(t, result, 3)
	assert.Equal(t, "alpha", result[0].Name)
	assert.Equal(t, "bravo", result[1].Name)
	assert.Equal(t, "charlie", result[2].Name)
}

func TestPolicyRouter_Update_MultiplePolicies(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr.SetContext(ctx)

	policies := []v1alpha1.NotificationPolicy{
		makePolicy("critical-alerts", "http://critical.example.com/hook", "Critical", "summary"),
		makePolicy("all-alerts", "http://all.example.com/hook", "Info", "detailed"),
	}

	pr.Update(policies, nil)

	senders := pr.SendersForPolicies()
	assert.Len(t, senders, 2)
}

func TestPolicyRouter_Update_RemovesStaleSenders(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr.SetContext(ctx)

	// Initial update with two policies.
	pr.Update([]v1alpha1.NotificationPolicy{
		makePolicy("alpha", "http://a.example.com/hook", "Warning", "summary"),
		makePolicy("bravo", "http://b.example.com/hook", "Warning", "summary"),
	}, nil)
	assert.Len(t, pr.SendersForPolicies(), 2)

	// Update with only one policy — bravo should be removed.
	pr.Update([]v1alpha1.NotificationPolicy{
		makePolicy("alpha", "http://a.example.com/hook", "Warning", "summary"),
	}, nil)
	assert.Len(t, pr.SendersForPolicies(), 1)
}

func TestPolicyRouter_Update_ReplacesChangedConfig(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr.SetContext(ctx)

	pr.Update([]v1alpha1.NotificationPolicy{
		makePolicy("alpha", "http://old.example.com/hook", "Warning", "summary"),
	}, nil)

	senders1 := pr.SendersForPolicies()
	require.Len(t, senders1, 1)

	// Update with changed URL.
	pr.Update([]v1alpha1.NotificationPolicy{
		makePolicy("alpha", "http://new.example.com/hook", "Warning", "summary"),
	}, nil)

	senders2 := pr.SendersForPolicies()
	require.Len(t, senders2, 1)
	assert.Equal(t, "http://new.example.com/hook", webhookSenderURL(t, senders2))
}

func TestPolicyRouter_Update_KeepsUnchangedSenders(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr.SetContext(ctx)

	pr.Update([]v1alpha1.NotificationPolicy{
		makePolicy("alpha", "http://example.com/hook", "Warning", "summary"),
	}, nil)

	senders1 := pr.SendersForPolicies()
	require.Len(t, senders1, 1)
	ptr1 := senders1[0]

	// Update with same config — sender should be reused.
	pr.Update([]v1alpha1.NotificationPolicy{
		makePolicy("alpha", "http://example.com/hook", "Warning", "summary"),
	}, nil)

	senders2 := pr.SendersForPolicies()
	require.Len(t, senders2, 1)
	assert.Same(t, ptr1, senders2[0], "Unchanged sender should be reused")
}

func TestPolicyRouter_Update_DisabledWebhook(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())

	p := v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled"},
		Spec: v1alpha1.NotificationPolicySpec{
			Channels: v1alpha1.NotificationChannels{
				Webhook: &v1alpha1.WebhookConfig{
					Enabled: false,
					URL:     "http://example.com/hook",
				},
			},
		},
	}

	pr.Update([]v1alpha1.NotificationPolicy{p}, nil)

	assert.Nil(t, pr.SendersForPolicies())
}

func TestPolicyRouter_Update_NoChannels(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())

	p := v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "no-channels"},
		Spec: v1alpha1.NotificationPolicySpec{
			DeveloperScope: v1alpha1.NotificationScope{
				MaxDetailLevel: "detailed",
			},
		},
	}

	pr.Update([]v1alpha1.NotificationPolicy{p}, nil)

	assert.Len(t, pr.Policies(), 1)
	assert.Nil(t, pr.SendersForPolicies())
}

func TestPolicyRouter_Update_SlackWarning(t *testing.T) {
	// Slack is not implemented — should log warning and not create a sender.
	pr := NewPolicyRouter(zap.NewNop())

	p := v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "with-slack"},
		Spec: v1alpha1.NotificationPolicySpec{
			Channels: v1alpha1.NotificationChannels{
				Slack: &v1alpha1.SlackConfig{
					Enabled:    true,
					WebhookURL: "https://hooks.slack.com/services/XXX",
				},
			},
		},
	}

	pr.Update([]v1alpha1.NotificationPolicy{p}, nil)

	assert.Nil(t, pr.SendersForPolicies())
}

func TestPolicyRouter_Update_AuthToken(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr.SetContext(ctx)

	p := v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "with-auth"},
		Spec: v1alpha1.NotificationPolicySpec{
			Channels: v1alpha1.NotificationChannels{
				Webhook: &v1alpha1.WebhookConfig{
					Enabled: true,
					URL:     "http://example.com/hook",
					AuthSecretRef: &v1alpha1.SecretKeyReference{
						Name: "my-secret",
						Key:  "token",
					},
				},
			},
		},
	}

	tokens := map[string]string{"with-auth": "my-token-value"}
	pr.Update([]v1alpha1.NotificationPolicy{p}, tokens)

	senders := pr.SendersForPolicies()
	require.Len(t, senders, 1)
	ws, ok := senders[0].(*WebhookSender)
	require.True(t, ok)
	assert.Equal(t, "my-token-value", ws.authToken)
}

func TestPolicyRouter_DetailLevel_Default(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	assert.Equal(t, types.DetailLevelSummary, pr.DetailLevel(types.DetailLevelSummary))
}

func TestPolicyRouter_DetailLevel_FromPolicy(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())

	pr.Update([]v1alpha1.NotificationPolicy{
		makePolicy("default", "", "", "detailed"),
	}, nil)

	assert.Equal(t, types.DetailLevelDetailed, pr.DetailLevel(types.DetailLevelSummary))
}

func TestPolicyRouter_DetailLevel_EmptyFallback(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())

	pr.Update([]v1alpha1.NotificationPolicy{
		makePolicy("default", "", "", ""),
	}, nil)

	assert.Equal(t, types.DetailLevelSummary, pr.DetailLevel(types.DetailLevelSummary))
}

func TestPolicyRouter_Contact(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())

	p := v1alpha1.NotificationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: v1alpha1.NotificationPolicySpec{
			DeveloperScope: v1alpha1.NotificationScope{
				Contact: "platform-team@example.com",
			},
		},
	}

	pr.Update([]v1alpha1.NotificationPolicy{p}, nil)
	assert.Equal(t, "platform-team@example.com", pr.Contact())
}

func TestPolicyRouter_Contact_Empty(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	assert.Equal(t, "", pr.Contact())
}

func TestPolicyRouter_Close(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr.SetContext(ctx)

	pr.Update([]v1alpha1.NotificationPolicy{
		makePolicy("alpha", "http://example.com/hook", "Warning", "summary"),
	}, nil)
	assert.Len(t, pr.SendersForPolicies(), 1)

	pr.Close()
	assert.Nil(t, pr.SendersForPolicies())
}

func TestPolicyRouter_ConcurrentAccess(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr.SetContext(ctx)

	const goroutines = 50
	var wg sync.WaitGroup

	// Writer goroutines.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pr.Update([]v1alpha1.NotificationPolicy{
				makePolicy("concurrent", "http://example.com/hook", "Warning", "summary"),
			}, nil)
		}()
	}

	// Reader goroutines.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = pr.Policies()
			_ = pr.DetailLevel(types.DetailLevelSummary)
			_ = pr.SendersForPolicies()
			_ = pr.Contact()
		}()
	}

	wg.Wait()

	// Should not panic and should have consistent state.
	policies := pr.Policies()
	assert.Len(t, policies, 1)
}

func TestPolicyRouter_Update_ClearsAllOnEmpty(t *testing.T) {
	pr := NewPolicyRouter(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr.SetContext(ctx)

	pr.Update([]v1alpha1.NotificationPolicy{
		makePolicy("alpha", "http://example.com/hook", "Warning", "summary"),
	}, nil)
	assert.Len(t, pr.Policies(), 1)
	assert.Len(t, pr.SendersForPolicies(), 1)

	// Empty update should remove everything.
	pr.Update(nil, nil)
	assert.Empty(t, pr.Policies())
	assert.Nil(t, pr.SendersForPolicies())
}
