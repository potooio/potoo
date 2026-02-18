package webhook

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDefaultCertManagerConfig(t *testing.T) {
	config := DefaultCertManagerConfig("test-ns")

	assert.Equal(t, CertModeSelfSigned, config.Mode)
	assert.Equal(t, "test-ns", config.Namespace)
	assert.Equal(t, "potoo-webhook", config.ServiceName)
	assert.Equal(t, DefaultSecretName, config.SecretName)
	assert.Equal(t, DefaultWebhookConfigName, config.WebhookConfigName)
}

func TestCertManager_EnsureCertificates_SelfSigned_CreateNew(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()

	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "potoo-system",
		ServiceName:       "potoo-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	cm := NewCertManager(client, config, logger)
	ctx := context.Background()

	// First call should create the secret
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Verify secret was created
	secret, err := client.CoreV1().Secrets(config.Namespace).Get(ctx, config.SecretName, metav1.GetOptions{})
	require.NoError(t, err)

	assert.NotEmpty(t, secret.Data["ca.crt"])
	assert.NotEmpty(t, secret.Data["tls.crt"])
	assert.NotEmpty(t, secret.Data["tls.key"])
	assert.Equal(t, corev1.SecretTypeTLS, secret.Type)

	// Verify certificates are valid
	caCert, serverCert, serverKey := cm.GetCertificates()
	assert.NotEmpty(t, caCert)
	assert.NotEmpty(t, serverCert)
	assert.NotEmpty(t, serverKey)

	// Parse and verify server certificate
	block, _ := pem.Decode(serverCert)
	require.NotNil(t, block, "failed to decode server cert PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Check DNS names include the service name
	assert.Contains(t, cert.DNSNames, config.ServiceName)
	assert.Contains(t, cert.DNSNames, config.ServiceName+"."+config.Namespace+".svc")

	// Check validity period
	assert.True(t, cert.NotAfter.After(time.Now().Add(CertValidityDuration-time.Hour)))
}

func TestCertManager_EnsureCertificates_SelfSigned_UseExisting(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()

	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "potoo-system",
		ServiceName:       "potoo-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	cm := NewCertManager(client, config, logger)
	ctx := context.Background()

	// Create initial certificates
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	initialCert, _, _ := cm.GetCertificates()

	// Create a new CertManager and ensure again
	cm2 := NewCertManager(client, config, logger)
	err = cm2.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Should reuse existing certificates
	cert2, _, _ := cm2.GetCertificates()
	assert.Equal(t, initialCert, cert2, "should reuse existing valid certificates")
}

func TestCertManager_EnsureCertificates_CertManager_SecretExists(t *testing.T) {
	ctx := context.Background()

	// Pre-create secret as if cert-manager created it
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-tls",
			Namespace: "potoo-system",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"ca.crt":  []byte("fake-ca-cert"),
			"tls.crt": []byte("fake-server-cert"),
			"tls.key": []byte("fake-server-key"),
		},
	}

	client := fake.NewSimpleClientset(secret)
	logger := zap.NewNop()

	config := CertManagerConfig{
		Mode:              CertModeCertManager,
		Namespace:         "potoo-system",
		ServiceName:       "potoo-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	cm := NewCertManager(client, config, logger)

	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	caCert, serverCert, serverKey := cm.GetCertificates()
	assert.Equal(t, []byte("fake-ca-cert"), caCert)
	assert.Equal(t, []byte("fake-server-cert"), serverCert)
	assert.Equal(t, []byte("fake-server-key"), serverKey)
}

func TestCertManager_EnsureCertificates_CertManager_SecretMissing(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()

	config := CertManagerConfig{
		Mode:              CertModeCertManager,
		Namespace:         "potoo-system",
		ServiceName:       "potoo-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	cm := NewCertManager(client, config, logger)
	ctx := context.Background()

	err := cm.EnsureCertificates(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCertManager_UpdateWebhookCABundle(t *testing.T) {
	ctx := context.Background()

	// Create webhook configuration
	failurePolicy := admissionregistrationv1.Ignore
	sideEffects := admissionregistrationv1.SideEffectClassNone
	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "test.potoo.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte("old-ca"),
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	client := fake.NewSimpleClientset(webhookConfig)
	logger := zap.NewNop()

	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "potoo-system",
		ServiceName:       "potoo-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	cm := NewCertManager(client, config, logger)

	// Generate certificates first
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Update webhook CA bundle
	err = cm.UpdateWebhookCABundle(ctx)
	require.NoError(t, err)

	// Verify webhook was updated
	updated, err := client.AdmissionregistrationV1().
		ValidatingWebhookConfigurations().
		Get(ctx, config.WebhookConfigName, metav1.GetOptions{})
	require.NoError(t, err)

	assert.Equal(t, cm.GetCABundle(), updated.Webhooks[0].ClientConfig.CABundle)
}

func TestCertManager_UpdateWebhookCABundle_WebhookNotFound(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()

	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "potoo-system",
		ServiceName:       "potoo-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	cm := NewCertManager(client, config, logger)
	ctx := context.Background()

	// Generate certificates first
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Should return an error when webhook doesn't exist so callers can retry.
	err = cm.UpdateWebhookCABundle(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCertManager_NeedsRotation(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()

	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "potoo-system",
		ServiceName:       "potoo-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	cm := NewCertManager(client, config, logger)
	ctx := context.Background()

	// No secret exists - needs rotation
	needs, err := cm.NeedsRotation(ctx)
	require.NoError(t, err)
	assert.True(t, needs, "should need rotation when secret doesn't exist")

	// Create certificates
	err = cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	// With valid certs - doesn't need rotation
	needs, err = cm.NeedsRotation(ctx)
	require.NoError(t, err)
	assert.False(t, needs, "should not need rotation with valid certs")
}

func TestCertManager_GenerateCA(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()

	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	certPEM, keyPEM, err := cm.generateCA()
	require.NoError(t, err)

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.True(t, cert.IsCA)
	assert.Equal(t, "Potoo Webhook CA", cert.Subject.CommonName)
	assert.Contains(t, cert.Subject.Organization, "Potoo")

	// Parse key
	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock)

	_, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
}

func TestCertManager_GenerateServerCert(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()

	config := CertManagerConfig{
		Mode:        CertModeSelfSigned,
		Namespace:   "test-ns",
		ServiceName: "my-webhook",
	}
	cm := NewCertManager(client, config, logger)

	// Generate CA first
	caCertPEM, caKeyPEM, err := cm.generateCA()
	require.NoError(t, err)

	// Generate server cert
	serverCertPEM, serverKeyPEM, err := cm.generateServerCert(caCertPEM, caKeyPEM)
	require.NoError(t, err)

	// Parse server certificate
	block, _ := pem.Decode(serverCertPEM)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.False(t, cert.IsCA)
	assert.Equal(t, config.ServiceName, cert.Subject.CommonName)

	// Check DNS SANs
	expectedDNS := []string{
		"my-webhook",
		"my-webhook.test-ns",
		"my-webhook.test-ns.svc",
		"my-webhook.test-ns.svc.cluster.local",
	}
	for _, dns := range expectedDNS {
		assert.Contains(t, cert.DNSNames, dns)
	}

	// Verify key can be parsed
	keyBlock, _ := pem.Decode(serverKeyPEM)
	require.NotNil(t, keyBlock)

	_, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)

	// Verify certificate is signed by CA
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	require.NoError(t, err, "server cert should be verified by CA")
}

// --- New tests to boost coverage ---

func TestAreCertsValid_EmptyCert(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	secret := &corev1.Secret{
		Data: map[string][]byte{
			"tls.crt": nil,
		},
	}

	assert.False(t, cm.areCertsValid(secret))
}

func TestAreCertsValid_InvalidPEM(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	secret := &corev1.Secret{
		Data: map[string][]byte{
			"tls.crt": []byte("not a valid PEM"),
		},
	}

	assert.False(t, cm.areCertsValid(secret))
}

func TestAreCertsValid_InvalidCertDER(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	// Valid PEM block but with garbage DER content
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("garbage bytes that are not valid DER"),
	})

	secret := &corev1.Secret{
		Data: map[string][]byte{
			"tls.crt": invalidPEM,
		},
	}

	assert.False(t, cm.areCertsValid(secret))
}

func TestAreCertsValid_ExpiredCert(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	// Generate a certificate that expires very soon (before rotation threshold)
	caCertPEM, caKeyPEM, err := cm.generateCA()
	require.NoError(t, err)

	// Parse the CA for signing
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)

	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)

	// Create a server cert that expires in 1 day (within 30 day rotation threshold)
	import_rand_reader := func() *big.Int {
		n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		return n
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: import_rand_reader(),
		Subject: pkix.Name{
			Organization: []string{"Test"},
			CommonName:   "test",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour), // Expires in 1 day, within 30d threshold
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	expiringSoonPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	secret := &corev1.Secret{
		Data: map[string][]byte{
			"tls.crt": expiringSoonPEM,
		},
	}

	assert.False(t, cm.areCertsValid(secret), "Certificate expiring within rotation threshold should be invalid")
}

func TestAreCertsValid_ValidCert(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)
	ctx := context.Background()

	// Generate valid certificates
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Create a secret with the valid cert
	secret := &corev1.Secret{
		Data: map[string][]byte{
			"tls.crt": cm.serverCert,
		},
	}

	assert.True(t, cm.areCertsValid(secret), "Valid non-expiring cert should be valid")
}

func TestNeedsRotation_CertExpiringSoon(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "test-ns",
		ServiceName:       "test-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}
	cm := NewCertManager(client, config, logger)
	ctx := context.Background()

	// Generate certs first
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Now replace the secret with a near-expiry cert
	caCertPEM, caKeyPEM, err := cm.generateCA()
	require.NoError(t, err)

	caBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, _ := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)

	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour), // 7 days, within 30d threshold
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"test-webhook"},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	expiringCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	expiringKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	// Update the secret with the expiring cert
	secret, err := client.CoreV1().Secrets(config.Namespace).Get(ctx, config.SecretName, metav1.GetOptions{})
	require.NoError(t, err)

	secret.Data["tls.crt"] = expiringCertPEM
	secret.Data["tls.key"] = expiringKeyPEM
	_, err = client.CoreV1().Secrets(config.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Should need rotation
	needs, err := cm.NeedsRotation(ctx)
	require.NoError(t, err)
	assert.True(t, needs, "Certificate expiring within threshold should need rotation")
}

func TestGenerateCA_ValidProperties(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test-ns")
	cm := NewCertManager(client, config, logger)

	certPEM, keyPEM, err := cm.generateCA()
	require.NoError(t, err)
	require.NotEmpty(t, certPEM)
	require.NotEmpty(t, keyPEM)

	// Parse and verify certificate properties
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// CA-specific properties
	assert.True(t, cert.IsCA)
	assert.True(t, cert.BasicConstraintsValid)
	// MaxPathLen 0 in template without MaxPathLenZero=true results in -1 (unconstrained) when parsed
	assert.True(t, cert.MaxPathLen <= 0, "MaxPathLen should be 0 or -1 for a root CA")
	assert.Equal(t, "Potoo Webhook CA", cert.Subject.CommonName)
	assert.Contains(t, cert.Subject.Organization, "Potoo")

	// Key usage
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign)
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCRLSign)

	// Validity period
	assert.True(t, cert.NotBefore.Before(time.Now()))
	assert.True(t, cert.NotAfter.After(time.Now().Add(CertValidityDuration-2*time.Hour)))

	// Verify the key is parseable
	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock)

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	assert.Equal(t, 2048, key.N.BitLen())
}

func TestGenerateServerCert_ValidSANs(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := CertManagerConfig{
		Mode:        CertModeSelfSigned,
		Namespace:   "custom-ns",
		ServiceName: "custom-webhook",
	}
	cm := NewCertManager(client, config, logger)

	// Generate CA first
	caCertPEM, caKeyPEM, err := cm.generateCA()
	require.NoError(t, err)

	// Generate server cert
	serverCertPEM, serverKeyPEM, err := cm.generateServerCert(caCertPEM, caKeyPEM)
	require.NoError(t, err)

	// Parse server certificate
	block, _ := pem.Decode(serverCertPEM)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Verify it's NOT a CA
	assert.False(t, cert.IsCA)

	// Verify common name
	assert.Equal(t, "custom-webhook", cert.Subject.CommonName)

	// Verify all expected DNS SANs
	expectedDNS := []string{
		"custom-webhook",
		"custom-webhook.custom-ns",
		"custom-webhook.custom-ns.svc",
		"custom-webhook.custom-ns.svc.cluster.local",
	}
	for _, dns := range expectedDNS {
		assert.Contains(t, cert.DNSNames, dns, "Missing expected DNS SAN: %s", dns)
	}

	// Verify key usage
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageDigitalSignature)
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageKeyEncipherment)

	// Verify extended key usage
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	// Verify server key is parseable
	keyBlock, _ := pem.Decode(serverKeyPEM)
	require.NotNil(t, keyBlock)

	_, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)

	// Verify the cert chain: server cert should be signed by CA
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	_, err = cert.Verify(x509.VerifyOptions{Roots: roots})
	require.NoError(t, err, "Server cert should be verifiable by CA")
}

func TestEnsureCertificates_UnknownMode(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := CertManagerConfig{
		Mode:      CertMode("unknown-mode"),
		Namespace: "test",
	}
	cm := NewCertManager(client, config, logger)
	ctx := context.Background()

	err := cm.EnsureCertificates(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown cert mode")
}

func TestEnsureSelfSignedCerts_RegeneratesExpiring(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "test-ns",
		ServiceName:       "test-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}
	cm := NewCertManager(client, config, logger)
	ctx := context.Background()

	// Create initial certificates
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	initialCert := cm.serverCert

	// Replace with a near-expiry cert in the secret
	caCertPEM, caKeyPEM, _ := cm.generateCA()
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, _ := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)

	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-350 * 24 * time.Hour),
		NotAfter:     time.Now().Add(5 * 24 * time.Hour), // Expires in 5 days
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"test-webhook"},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	expiringPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	expiringKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	// Update the secret with expiring cert
	secret, _ := client.CoreV1().Secrets(config.Namespace).Get(ctx, config.SecretName, metav1.GetOptions{})
	secret.Data["tls.crt"] = expiringPEM
	secret.Data["tls.key"] = expiringKeyPEM
	client.CoreV1().Secrets(config.Namespace).Update(ctx, secret, metav1.UpdateOptions{})

	// Create a new CertManager and ensure certs - should regenerate
	cm2 := NewCertManager(client, config, logger)
	err = cm2.EnsureCertificates(ctx)
	require.NoError(t, err)

	// The cert should be different from the expiring one
	assert.NotEqual(t, initialCert, cm2.serverCert, "Should have regenerated certificates")

	// New cert should be valid
	newCert := cm2.serverCert
	block, _ := pem.Decode(newCert)
	require.NotNil(t, block)

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, parsedCert.NotAfter.After(time.Now().Add(CertRotationThreshold)),
		"New cert should be valid beyond the rotation threshold")
}

func TestUpdateWebhookCABundle_NoCACert(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")

	cm := NewCertManager(client, config, logger)
	// Do NOT call EnsureCertificates - so caCert is empty

	err := cm.UpdateWebhookCABundle(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no CA certificate available")
}

func TestUpdateWebhookCABundle_AlreadyUpToDate(t *testing.T) {
	ctx := context.Background()

	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "test-ns",
		ServiceName:       "test-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	cm := NewCertManager(client, config, logger)

	// Generate certificates
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Create webhook with CORRECT CA bundle already set
	failurePolicy := admissionregistrationv1.Ignore
	sideEffects := admissionregistrationv1.SideEffectClassNone
	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "test.potoo.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: cm.GetCABundle(), // Already up to date
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	_, err = client.AdmissionregistrationV1().
		ValidatingWebhookConfigurations().
		Create(ctx, webhookConfig, metav1.CreateOptions{})
	require.NoError(t, err)

	// Should succeed without error (short-circuit since already up to date)
	err = cm.UpdateWebhookCABundle(ctx)
	assert.NoError(t, err)
}

func TestEnsureCertManagerCerts_MissingCertData(t *testing.T) {
	ctx := context.Background()

	// Create a secret with empty tls.crt
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-tls",
			Namespace: "test-ns",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"ca.crt":  []byte("some-ca"),
			"tls.crt": nil, // Missing
			"tls.key": []byte("some-key"),
		},
	}

	client := fake.NewSimpleClientset(secret)
	logger := zap.NewNop()

	config := CertManagerConfig{
		Mode:       CertModeCertManager,
		Namespace:  "test-ns",
		SecretName: "test-tls",
	}

	cm := NewCertManager(client, config, logger)

	err := cm.EnsureCertificates(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing tls.crt or tls.key")
}

func TestGetCABundle_Empty(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	// Before EnsureCertificates, CA bundle should be nil
	assert.Nil(t, cm.GetCABundle())
}

func TestGetCertificates_Empty(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	ca, cert, key := cm.GetCertificates()
	assert.Nil(t, ca)
	assert.Nil(t, cert)
	assert.Nil(t, key)
}

func TestCreateWebhookConfiguration(t *testing.T) {
	caBundle := []byte("test-ca-bundle")
	config := CreateWebhookConfiguration("potoo-system", "potoo-webhook", "potoo-webhook", caBundle)

	assert.Equal(t, "potoo-webhook", config.Name)
	require.Len(t, config.Webhooks, 1)

	webhook := config.Webhooks[0]
	assert.Equal(t, "constraint-warning.potoo.io", webhook.Name)
	assert.Equal(t, caBundle, webhook.ClientConfig.CABundle)
	assert.Equal(t, "potoo-system", webhook.ClientConfig.Service.Namespace)
	assert.Equal(t, "potoo-webhook", webhook.ClientConfig.Service.Name)
	assert.Equal(t, "/validate", *webhook.ClientConfig.Service.Path)

	// Verify fail-open policy
	assert.Equal(t, admissionregistrationv1.Ignore, *webhook.FailurePolicy)

	// Verify timeout
	assert.Equal(t, int32(5), *webhook.TimeoutSeconds)
}

// --- Additional tests to boost coverage ---

func TestStartRotationWatcher_CertManagerMode(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := CertManagerConfig{
		Mode:      CertModeCertManager,
		Namespace: "test-ns",
	}

	cm := NewCertManager(client, config, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// For cert-manager mode, the watcher should return immediately (no goroutine)
	cm.StartRotationWatcher(ctx, 100*time.Millisecond)

	// If it didn't block, the test passes
}

func TestStartRotationWatcher_SelfSigned_NoRotationNeeded(t *testing.T) {
	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "test-ns",
		ServiceName:       "test-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	cm := NewCertManager(client, config, logger)
	ctx, cancel := context.WithCancel(context.Background())

	// Generate valid certs first
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Create webhook config so UpdateWebhookCABundle succeeds
	failurePolicy := admissionregistrationv1.Ignore
	sideEffects := admissionregistrationv1.SideEffectClassNone
	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "test-webhook"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "test.potoo.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: cm.GetCABundle(),
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}
	_, err = client.AdmissionregistrationV1().
		ValidatingWebhookConfigurations().
		Create(ctx, webhookConfig, metav1.CreateOptions{})
	require.NoError(t, err)

	// Start watcher with a very short interval
	cm.StartRotationWatcher(ctx, 50*time.Millisecond)

	// Let the watcher tick once
	time.Sleep(100 * time.Millisecond)

	// Cancel context to stop watcher
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestStartRotationWatcher_SelfSigned_NeedsRotation(t *testing.T) {
	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "test-ns",
		ServiceName:       "test-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	cm := NewCertManager(client, config, logger)
	ctx, cancel := context.WithCancel(context.Background())

	// Generate initial certs
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Replace the secret with an expiring cert to trigger rotation
	caCertPEM, caKeyPEM, _ := cm.generateCA()
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, _ := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)

	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-350 * 24 * time.Hour),
		NotAfter:     time.Now().Add(2 * 24 * time.Hour), // Expires in 2 days
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"test-webhook"},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	expiringPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	expiringKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	secret, _ := client.CoreV1().Secrets(config.Namespace).Get(ctx, config.SecretName, metav1.GetOptions{})
	secret.Data["tls.crt"] = expiringPEM
	secret.Data["tls.key"] = expiringKeyPEM
	_, err = client.CoreV1().Secrets(config.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	require.NoError(t, err)

	// Start watcher with very short interval so it triggers quickly
	cm.StartRotationWatcher(ctx, 50*time.Millisecond)

	// Wait for rotation to happen (give it several ticks)
	time.Sleep(500 * time.Millisecond)

	cancel()
	time.Sleep(50 * time.Millisecond)

	// Verify rotation by reading the secret (avoids racing on struct fields)
	rotatedSecret, err := client.CoreV1().Secrets(config.Namespace).Get(context.Background(), config.SecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.NotEqual(t, expiringPEM, rotatedSecret.Data["tls.crt"], "Server cert should have been rotated")
}

func TestGenerateServerCert_InvalidCACertPEM(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	_, _, err := cm.generateServerCert([]byte("not a PEM"), []byte("not a key PEM"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode CA certificate PEM")
}

func TestGenerateServerCert_InvalidCACertDER(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	invalidCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("garbage DER"),
	})

	_, _, err := cm.generateServerCert(invalidCertPEM, []byte("not a key PEM"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

func TestGenerateServerCert_InvalidCAKeyPEM(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	// Generate a valid CA cert but provide invalid key
	caCertPEM, _, err := cm.generateCA()
	require.NoError(t, err)

	_, _, err = cm.generateServerCert(caCertPEM, []byte("not a PEM key"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode CA key PEM")
}

func TestGenerateServerCert_InvalidCAKeyDER(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test")
	cm := NewCertManager(client, config, logger)

	caCertPEM, _, err := cm.generateCA()
	require.NoError(t, err)

	invalidKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("garbage key DER"),
	})

	_, _, err = cm.generateServerCert(caCertPEM, invalidKeyPEM)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA key")
}

func TestEnsureCertManagerCerts_MissingKeyData(t *testing.T) {
	ctx := context.Background()

	// Create a secret with valid tls.crt but missing tls.key
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-tls",
			Namespace: "test-ns",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"ca.crt":  []byte("some-ca"),
			"tls.crt": []byte("some-cert"),
			"tls.key": nil, // Missing
		},
	}

	client := fake.NewSimpleClientset(secret)
	logger := zap.NewNop()
	config := CertManagerConfig{
		Mode:       CertModeCertManager,
		Namespace:  "test-ns",
		SecretName: "test-tls",
	}

	cm := NewCertManager(client, config, logger)

	err := cm.EnsureCertificates(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing tls.crt or tls.key")
}

func TestNewCertManager(t *testing.T) {
	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	config := DefaultCertManagerConfig("test-ns")

	cm := NewCertManager(client, config, logger)

	require.NotNil(t, cm)
	assert.Equal(t, CertModeSelfSigned, cm.config.Mode)
	assert.Equal(t, "test-ns", cm.config.Namespace)
	assert.Equal(t, "potoo-webhook", cm.config.ServiceName)
}

func TestCreateWebhookConfiguration_Labels(t *testing.T) {
	config := CreateWebhookConfiguration("ns", "svc", "webhook-name", []byte("ca"))

	assert.Equal(t, "potoo", config.Labels["app.kubernetes.io/name"])
	assert.Equal(t, "webhook", config.Labels["app.kubernetes.io/component"])
}

func TestCreateWebhookConfiguration_Rules(t *testing.T) {
	config := CreateWebhookConfiguration("ns", "svc", "webhook-name", []byte("ca"))

	require.Len(t, config.Webhooks, 1)
	webhook := config.Webhooks[0]
	require.Len(t, webhook.Rules, 1)

	rule := webhook.Rules[0]
	assert.Contains(t, rule.Operations, admissionregistrationv1.Create)
	assert.Contains(t, rule.Operations, admissionregistrationv1.Update)
	assert.Equal(t, []string{"*"}, rule.APIGroups)
	assert.Equal(t, []string{"*"}, rule.APIVersions)
	assert.Contains(t, rule.Resources, "pods")
	assert.Contains(t, rule.Resources, "deployments")

	// SideEffects
	assert.Equal(t, admissionregistrationv1.SideEffectClassNone, *webhook.SideEffects)

	// Match policy
	assert.Equal(t, admissionregistrationv1.Equivalent, *webhook.MatchPolicy)

	// Port
	assert.Equal(t, int32(443), *webhook.ClientConfig.Service.Port)
}

func TestStrPtr(t *testing.T) {
	s := strPtr("hello")
	require.NotNil(t, s)
	assert.Equal(t, "hello", *s)
}

func TestInt32Ptr(t *testing.T) {
	i := int32Ptr(42)
	require.NotNil(t, i)
	assert.Equal(t, int32(42), *i)
}

func TestEnsureSelfSignedCerts_SecretExistsValidCerts(t *testing.T) {
	config := CertManagerConfig{
		Mode:              CertModeSelfSigned,
		Namespace:         "test-ns",
		ServiceName:       "test-webhook",
		SecretName:        "test-tls",
		WebhookConfigName: "test-webhook",
	}

	client := fake.NewSimpleClientset()
	logger := zap.NewNop()
	cm := NewCertManager(client, config, logger)
	ctx := context.Background()

	// Create certs first
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	origCert := cm.serverCert

	// Create new manager that should reuse certs
	cm2 := NewCertManager(client, config, logger)
	err = cm2.EnsureCertificates(ctx)
	require.NoError(t, err)

	// Should be the same cert
	assert.Equal(t, origCert, cm2.serverCert, "Should reuse existing valid certificates")
}

func TestEnsureCertManagerCerts_ValidData(t *testing.T) {
	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-tls",
			Namespace: "test-ns",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"ca.crt":  []byte("test-ca"),
			"tls.crt": []byte("test-cert"),
			"tls.key": []byte("test-key"),
		},
	}

	client := fake.NewSimpleClientset(secret)
	logger := zap.NewNop()
	config := CertManagerConfig{
		Mode:       CertModeCertManager,
		Namespace:  "test-ns",
		SecretName: "test-tls",
	}

	cm := NewCertManager(client, config, logger)
	err := cm.EnsureCertificates(ctx)
	require.NoError(t, err)

	assert.Equal(t, []byte("test-ca"), cm.caCert)
	assert.Equal(t, []byte("test-cert"), cm.serverCert)
	assert.Equal(t, []byte("test-key"), cm.serverKey)
}
