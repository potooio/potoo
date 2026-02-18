package notifier

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	webhookSendTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "potoo_webhook_send_total",
			Help: "Total webhook notification send attempts by status.",
		},
		[]string{"status"},
	)
	webhookSendDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "potoo_webhook_send_duration_seconds",
			Help:    "Duration of webhook notification HTTP requests.",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		},
		[]string{"status"},
	)
)
