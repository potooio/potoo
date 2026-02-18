package notifier

import (
	"context"

	"github.com/potooio/potoo/internal/types"
)

// Sender is the interface for external notification channels (webhook, Slack, etc.).
// Each implementation handles its own async delivery, retry logic, and filtering.
type Sender interface {
	// Name returns the sender's identifier (e.g., "webhook", "slack").
	Name() string

	// Send delivers a notification payload to the external channel.
	Send(ctx context.Context, data EventStructuredData) error

	// ShouldSend returns true if this sender should handle a notification at the given severity.
	ShouldSend(severity types.Severity) bool

	// Start begins any background workers. Non-blocking.
	Start(ctx context.Context)
}
