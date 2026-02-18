package webhook

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"go.uber.org/zap"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// CertValidityDuration is how long certificates are valid.
	CertValidityDuration = 365 * 24 * time.Hour // 1 year

	// CertRotationThreshold is when to rotate before expiry.
	CertRotationThreshold = 30 * 24 * time.Hour // 30 days

	// DefaultSecretName is the name of the Secret storing TLS certs.
	DefaultSecretName = "potoo-webhook-tls"

	// DefaultWebhookConfigName is the name of the ValidatingWebhookConfiguration.
	DefaultWebhookConfigName = "potoo-webhook"
)

// CertMode specifies how certificates are managed.
type CertMode string

const (
	// CertModeSelfSigned means the operator manages its own CA and certs.
	CertModeSelfSigned CertMode = "self-signed"

	// CertModeCertManager means cert-manager handles certificate lifecycle.
	CertModeCertManager CertMode = "cert-manager"
)

// CertManagerConfig holds configuration for certificate management.
type CertManagerConfig struct {
	// Mode specifies self-signed or cert-manager.
	Mode CertMode

	// Namespace where the webhook and secret live.
	Namespace string

	// ServiceName is the webhook service name (for DNS SAN).
	ServiceName string

	// SecretName is the name of the TLS secret.
	SecretName string

	// WebhookConfigName is the name of the ValidatingWebhookConfiguration.
	WebhookConfigName string
}

// DefaultCertManagerConfig returns default configuration.
func DefaultCertManagerConfig(namespace string) CertManagerConfig {
	return CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         namespace,
		ServiceName:       "potoo-webhook",
		SecretName:        DefaultSecretName,
		WebhookConfigName: DefaultWebhookConfigName,
	}
}

// CertManager manages TLS certificates for the admission webhook.
type CertManager struct {
	client kubernetes.Interface
	config CertManagerConfig
	logger *zap.Logger

	// Current certificate state (populated after EnsureCertificates)
	caCert     []byte
	serverCert []byte
	serverKey  []byte
}

// NewCertManager creates a new certificate manager.
func NewCertManager(client kubernetes.Interface, config CertManagerConfig, logger *zap.Logger) *CertManager {
	return &CertManager{
		client: client,
		config: config,
		logger: logger.Named("cert-manager"),
	}
}

// EnsureCertificates ensures TLS certificates exist and are valid.
// For self-signed mode, it generates certificates if missing or expiring.
// For cert-manager mode, it verifies the secret exists.
func (m *CertManager) EnsureCertificates(ctx context.Context) error {
	switch m.config.Mode {
	case CertModeSelfSigned:
		return m.ensureSelfSignedCerts(ctx)
	case CertModeCertManager:
		return m.ensureCertManagerCerts(ctx)
	default:
		return fmt.Errorf("unknown cert mode: %s", m.config.Mode)
	}
}

// GetCertificates returns the current TLS certificates.
// Returns (caCert, serverCert, serverKey).
func (m *CertManager) GetCertificates() ([]byte, []byte, []byte) {
	return m.caCert, m.serverCert, m.serverKey
}

// GetCABundle returns the CA certificate for the webhook configuration.
func (m *CertManager) GetCABundle() []byte {
	return m.caCert
}

// UpdateWebhookCABundle patches the ValidatingWebhookConfiguration with the CA bundle.
func (m *CertManager) UpdateWebhookCABundle(ctx context.Context) error {
	if len(m.caCert) == 0 {
		return fmt.Errorf("no CA certificate available")
	}

	webhookConfig, err := m.client.AdmissionregistrationV1().
		ValidatingWebhookConfigurations().
		Get(ctx, m.config.WebhookConfigName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			m.logger.Info("Webhook configuration not found, will retry",
				zap.String("name", m.config.WebhookConfigName))
			return fmt.Errorf("webhook configuration %s not found: %w", m.config.WebhookConfigName, err)
		}
		return fmt.Errorf("failed to get webhook configuration: %w", err)
	}

	// Update CA bundle for all webhooks
	updated := false
	for i := range webhookConfig.Webhooks {
		if !bytes.Equal(webhookConfig.Webhooks[i].ClientConfig.CABundle, m.caCert) {
			webhookConfig.Webhooks[i].ClientConfig.CABundle = m.caCert
			updated = true
		}
	}

	if !updated {
		m.logger.Debug("Webhook CA bundle already up to date")
		return nil
	}

	_, err = m.client.AdmissionregistrationV1().
		ValidatingWebhookConfigurations().
		Update(ctx, webhookConfig, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update webhook configuration: %w", err)
	}

	m.logger.Info("Updated webhook CA bundle",
		zap.String("name", m.config.WebhookConfigName))
	return nil
}

// ensureSelfSignedCerts generates and stores self-signed certificates.
func (m *CertManager) ensureSelfSignedCerts(ctx context.Context) error {
	secret, getErr := m.client.CoreV1().Secrets(m.config.Namespace).
		Get(ctx, m.config.SecretName, metav1.GetOptions{})

	secretExists := getErr == nil
	if getErr == nil {
		// Secret exists, check if certificates are still valid
		if m.areCertsValid(secret) {
			m.caCert = secret.Data["ca.crt"]
			m.serverCert = secret.Data["tls.crt"]
			m.serverKey = secret.Data["tls.key"]
			m.logger.Debug("Using existing certificates from secret")
			return nil
		}
		m.logger.Info("Certificates expiring or invalid, regenerating")
	} else if !apierrors.IsNotFound(getErr) {
		return fmt.Errorf("failed to get secret: %w", getErr)
	}

	// Generate new certificates
	m.logger.Info("Generating self-signed certificates")
	caCert, caKey, err := m.generateCA()
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}

	serverCert, serverKey, err := m.generateServerCert(caCert, caKey)
	if err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// Create or update secret
	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.config.SecretName,
			Namespace: m.config.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "potoo",
				"app.kubernetes.io/component": "webhook",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"ca.crt":  caCert,
			"tls.crt": serverCert,
			"tls.key": serverKey,
		},
	}

	if secretExists {
		_, err = m.client.CoreV1().Secrets(m.config.Namespace).
			Update(ctx, newSecret, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}
		m.logger.Info("Updated TLS secret", zap.String("name", m.config.SecretName))
	} else {
		_, err = m.client.CoreV1().Secrets(m.config.Namespace).
			Create(ctx, newSecret, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
		m.logger.Info("Created TLS secret", zap.String("name", m.config.SecretName))
	}

	m.caCert = caCert
	m.serverCert = serverCert
	m.serverKey = serverKey

	return nil
}

// ensureCertManagerCerts verifies cert-manager has created the certificates.
func (m *CertManager) ensureCertManagerCerts(ctx context.Context) error {
	secret, err := m.client.CoreV1().Secrets(m.config.Namespace).
		Get(ctx, m.config.SecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("cert-manager secret %s/%s not found; ensure Certificate resource is created",
				m.config.Namespace, m.config.SecretName)
		}
		return fmt.Errorf("failed to get secret: %w", err)
	}

	m.caCert = secret.Data["ca.crt"]
	m.serverCert = secret.Data["tls.crt"]
	m.serverKey = secret.Data["tls.key"]

	if len(m.serverCert) == 0 || len(m.serverKey) == 0 {
		return fmt.Errorf("cert-manager secret missing tls.crt or tls.key")
	}

	m.logger.Debug("Using certificates from cert-manager")
	return nil
}

// areCertsValid checks if existing certificates are valid and not expiring soon.
func (m *CertManager) areCertsValid(secret *corev1.Secret) bool {
	certPEM := secret.Data["tls.crt"]
	if len(certPEM) == 0 {
		return false
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	// Check if certificate expires within the rotation threshold
	rotationTime := time.Now().Add(CertRotationThreshold)
	if cert.NotAfter.Before(rotationTime) {
		m.logger.Info("Certificate expiring soon",
			zap.Time("expires", cert.NotAfter),
			zap.Duration("threshold", CertRotationThreshold))
		return false
	}

	return true
}

// generateCA creates a new CA certificate and key.
func (m *CertManager) generateCA() (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Potoo"},
			CommonName:   "Potoo Webhook CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(CertValidityDuration),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPEM, keyPEM, nil
}

// generateServerCert creates a server certificate signed by the CA.
func (m *CertManager) generateServerCert(caCertPEM, caKeyPEM []byte) (certPEM, keyPEM []byte, err error) {
	// Parse CA certificate
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA key
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Generate server key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Build DNS names for the certificate
	dnsNames := []string{
		m.config.ServiceName,
		fmt.Sprintf("%s.%s", m.config.ServiceName, m.config.Namespace),
		fmt.Sprintf("%s.%s.svc", m.config.ServiceName, m.config.Namespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", m.config.ServiceName, m.config.Namespace),
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Potoo"},
			CommonName:   m.config.ServiceName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(CertValidityDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	return certPEM, keyPEM, nil
}

// NeedsRotation checks if certificates need rotation.
func (m *CertManager) NeedsRotation(ctx context.Context) (bool, error) {
	secret, err := m.client.CoreV1().Secrets(m.config.Namespace).
		Get(ctx, m.config.SecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, fmt.Errorf("failed to get secret: %w", err)
	}

	return !m.areCertsValid(secret), nil
}

// StartRotationWatcher starts a background routine to check and rotate certificates.
func (m *CertManager) StartRotationWatcher(ctx context.Context, interval time.Duration) {
	if m.config.Mode != CertModeSelfSigned {
		m.logger.Debug("Certificate rotation handled by cert-manager, skipping watcher")
		return
	}

	go func() {
		// Ensure caBundle is synced once on startup in case the initial
		// attempt in main() raced with VWC creation.
		if err := m.UpdateWebhookCABundle(ctx); err != nil {
			m.logger.Warn("Initial caBundle sync in watcher failed, will retry on next tick",
				zap.Error(err))
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				needsRotation, err := m.NeedsRotation(ctx)
				if err != nil {
					m.logger.Error("Failed to check certificate rotation", zap.Error(err))
					continue
				}
				if needsRotation {
					m.logger.Info("Rotating certificates")
					if err := m.EnsureCertificates(ctx); err != nil {
						m.logger.Error("Failed to rotate certificates", zap.Error(err))
						continue
					}
				}
				// Always sync caBundle on each tick to recover from
				// transient failures (VWC recreation, etc.).
				if err := m.UpdateWebhookCABundle(ctx); err != nil {
					m.logger.Error("Failed to update webhook CA bundle", zap.Error(err))
				}
			}
		}
	}()
}

// CreateWebhookConfiguration creates the ValidatingWebhookConfiguration.
func CreateWebhookConfiguration(namespace, serviceName, webhookName string, caBundle []byte) *admissionregistrationv1.ValidatingWebhookConfiguration {
	failurePolicy := admissionregistrationv1.Ignore // Always fail-open
	sideEffects := admissionregistrationv1.SideEffectClassNone
	matchPolicy := admissionregistrationv1.Equivalent
	timeoutSeconds := int32(5) // Short timeout

	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: webhookName,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "potoo",
				"app.kubernetes.io/component": "webhook",
			},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "constraint-warning.potoo.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: namespace,
						Name:      serviceName,
						Path:      strPtr("/validate"),
						Port:      int32Ptr(443),
					},
					CABundle: caBundle,
				},
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"pods", "deployments", "services", "configmaps"},
						},
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
				MatchPolicy:             &matchPolicy,
				TimeoutSeconds:          &timeoutSeconds,
			},
		},
	}
}

func strPtr(s string) *string {
	return &s
}

func int32Ptr(i int32) *int32 {
	return &i
}
