//go:build integration
// +build integration

package integration

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	potoov1alpha1 "github.com/potooio/potoo/api/v1alpha1"
	"github.com/potooio/potoo/internal/adapters"
	"github.com/potooio/potoo/internal/adapters/gatekeeper"
	"github.com/potooio/potoo/internal/adapters/kyverno"
	"github.com/potooio/potoo/internal/adapters/networkpolicy"
	discoveryengine "github.com/potooio/potoo/internal/discovery"
	"github.com/potooio/potoo/internal/indexer"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = apiextensionsv1.AddToScheme(scheme)
	_ = potoov1alpha1.AddToScheme(scheme)
}

// IntegrationSuite is the base test suite for integration tests.
type IntegrationSuite struct {
	suite.Suite
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
	ctx       context.Context
	cancel    context.CancelFunc
	logger    *zap.Logger
	registry  *adapters.Registry
	idx       *indexer.Indexer
	engine    *discoveryengine.Engine
}

// SetupSuite runs once before all tests.
func (s *IntegrationSuite) SetupSuite() {
	s.logger = zap.NewNop()

	// Start envtest
	s.testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd"),
			filepath.Join("testdata", "crds"),
		},
		ErrorIfCRDPathMissing: false,
	}

	cfg, err := s.testEnv.Start()
	require.NoError(s.T(), err)
	s.cfg = cfg

	// Create client
	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(s.T(), err)
	s.k8sClient = k8sClient

	s.ctx, s.cancel = context.WithCancel(context.Background())
}

// TearDownSuite runs once after all tests.
func (s *IntegrationSuite) TearDownSuite() {
	s.cancel()
	if s.engine != nil {
		s.engine.Stop()
	}
	err := s.testEnv.Stop()
	require.NoError(s.T(), err)
}

// SetupTest runs before each test.
func (s *IntegrationSuite) SetupTest() {
	// Create fresh registry and indexer for each test
	s.registry = adapters.NewRegistry()
	s.idx = indexer.New(func(event indexer.IndexEvent) {
		// Log index events for debugging
	})
}

// TearDownTest runs after each test.
func (s *IntegrationSuite) TearDownTest() {
	if s.engine != nil {
		s.engine.Stop()
		s.engine = nil
	}
}

// startDiscoveryEngine starts the discovery engine with registered adapters.
func (s *IntegrationSuite) startDiscoveryEngine() {
	discoveryClient, err := s.testEnv.ControlPlane.RESTClientConfig()
	require.NoError(s.T(), err)

	// Get discovery and dynamic clients from config
	// Note: In a real test we would use the proper client creation
	// For now, we'll create a minimal test version
	s.T().Log("Starting discovery engine")

	// For integration tests, we would typically:
	// 1. Create the discovery engine with proper clients
	// 2. Start it in a goroutine
	// 3. Wait for initial sync
	_ = discoveryClient // Use this in actual implementation
}

// waitForConstraint waits for a constraint with the given name to appear in the indexer.
func (s *IntegrationSuite) waitForConstraint(name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		constraints := s.idx.All()
		for _, c := range constraints {
			if c.Name == name {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func TestIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(IntegrationSuite))
}

// GatekeeperSuite tests Gatekeeper integration.
type GatekeeperSuite struct {
	IntegrationSuite
}

// SetupTest registers the Gatekeeper adapter.
func (s *GatekeeperSuite) SetupTest() {
	s.IntegrationSuite.SetupTest()
	err := s.registry.Register(gatekeeper.New())
	require.NoError(s.T(), err)
}

func TestGatekeeperSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(GatekeeperSuite))
}

// KyvernoSuite tests Kyverno integration.
type KyvernoSuite struct {
	IntegrationSuite
}

// SetupTest registers the Kyverno adapter.
func (s *KyvernoSuite) SetupTest() {
	s.IntegrationSuite.SetupTest()
	err := s.registry.Register(kyverno.New())
	require.NoError(s.T(), err)
}

func TestKyvernoSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(KyvernoSuite))
}

// FullSuite tests with all adapters registered.
type FullSuite struct {
	IntegrationSuite
}

// SetupTest registers all adapters.
func (s *FullSuite) SetupTest() {
	s.IntegrationSuite.SetupTest()
	require.NoError(s.T(), s.registry.Register(networkpolicy.New()))
	require.NoError(s.T(), s.registry.Register(gatekeeper.New()))
	require.NoError(s.T(), s.registry.Register(kyverno.New()))
}

func TestFullSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(FullSuite))
}
