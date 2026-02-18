package hubble

import (
	"context"
	"net"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockObserverServer implements the Hubble Observer gRPC service for testing.
type mockObserverServer struct {
	observerpb.UnimplementedObserverServer
	flows []*flowpb.Flow
	// blockCh is closed to unblock a blocking GetFlows call.
	blockCh chan struct{}
}

func (m *mockObserverServer) GetFlows(_ *observerpb.GetFlowsRequest, stream observerpb.Observer_GetFlowsServer) error {
	for _, f := range m.flows {
		resp := &observerpb.GetFlowsResponse{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: f},
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
	// If blockCh is set, block until it's closed or context is done.
	if m.blockCh != nil {
		select {
		case <-m.blockCh:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
	return nil
}

// newMockObserverConn creates an in-process gRPC connection to a mock Observer server.
func newMockObserverConn(t *testing.T, srv *mockObserverServer) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	observerpb.RegisterObserverServer(s, srv)
	go func() {
		_ = s.Serve(lis)
	}()
	t.Cleanup(func() { s.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestDefaultClientOptions(t *testing.T) {
	opts := DefaultClientOptions()

	assert.Equal(t, "hubble-relay.kube-system.svc.cluster.local:4245", opts.RelayAddress)
	assert.Equal(t, time.Second, opts.ReconnectInterval)
	assert.Equal(t, time.Minute, opts.MaxReconnectInterval)
	assert.Equal(t, 1000, opts.BufferSize)
}

func TestNewClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: 100 * time.Millisecond,
		BufferSize:        10,
		Logger:            zap.NewNop(),
	}

	client, err := NewClient(ctx, opts)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Client should start in disconnected state and try to connect
	// Since there's no actual Hubble server, it will be in connecting/disconnected state
	state := client.State()
	assert.True(t, state == StateDisconnected || state == StateConnecting || state == StateReconnecting,
		"expected initial state, got %s", state)

	// Close the client
	err = client.Close()
	assert.NoError(t, err)
}

func TestClient_DroppedFlows(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := NewClient(ctx, ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: 100 * time.Millisecond,
		BufferSize:        10,
		Logger:            zap.NewNop(),
	})
	require.NoError(t, err)

	// Get the drops channel
	dropsChan := client.DroppedFlows()
	require.NotNil(t, dropsChan)

	// Close should close the channel
	client.Close()

	// Channel should be closed
	_, open := <-dropsChan
	assert.False(t, open, "drops channel should be closed after Close()")
}

func TestClient_Stats(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := NewClient(ctx, ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: 100 * time.Millisecond,
		BufferSize:        10,
		Logger:            zap.NewNop(),
	})
	require.NoError(t, err)
	defer client.Close()

	stats := client.Stats()
	// Initial state, no reconnects yet or just starting
	assert.GreaterOrEqual(t, stats.Reconnects, uint64(0))
	assert.Equal(t, uint64(0), stats.FlowDrops)
}

func TestClient_IsConnected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := NewClient(ctx, ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: 100 * time.Millisecond,
		BufferSize:        10,
		Logger:            zap.NewNop(),
	})
	require.NoError(t, err)
	defer client.Close()

	// Should not be connected (no actual server)
	assert.False(t, client.IsConnected())
}

func TestClient_nextReconnectInterval(t *testing.T) {
	client := &Client{
		opts: ClientOptions{
			ReconnectInterval:    time.Second,
			MaxReconnectInterval: 30 * time.Second,
		},
	}

	// Test exponential backoff
	interval := client.nextReconnectInterval(time.Second)
	assert.Equal(t, 2*time.Second, interval)

	interval = client.nextReconnectInterval(2 * time.Second)
	assert.Equal(t, 4*time.Second, interval)

	interval = client.nextReconnectInterval(4 * time.Second)
	assert.Equal(t, 8*time.Second, interval)

	// Test max cap
	interval = client.nextReconnectInterval(20 * time.Second)
	assert.Equal(t, 30*time.Second, interval)

	interval = client.nextReconnectInterval(30 * time.Second)
	assert.Equal(t, 30*time.Second, interval)
}

func TestClient_recordFlowDrop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := NewClient(ctx, ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: time.Hour, // Long interval to avoid reconnect noise
		BufferSize:        5,
		Logger:            zap.NewNop(),
	})
	require.NoError(t, err)
	defer client.Close()

	// Record a flow drop
	drop := NewFlowDropBuilder().
		WithSource("production", "frontend-abc", map[string]string{"app": "frontend"}).
		WithDestination("production", "backend-xyz", map[string]string{"app": "backend"}).
		WithTCP(45678, 8080, TCPFlags{SYN: true}).
		WithDropReason(DropReasonPolicy).
		Build()

	client.recordFlowDrop(drop)

	// Should be able to receive the drop
	select {
	case received := <-client.DroppedFlows():
		assert.Equal(t, "frontend-abc", received.Source.PodName)
		assert.Equal(t, "backend-xyz", received.Destination.PodName)
		assert.Equal(t, DropReasonPolicy, received.DropReason)
		assert.Equal(t, uint32(8080), received.L4.DestinationPort)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for flow drop")
	}

	// Check stats
	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.FlowDrops)
}

func TestNewClient_DefaultOptions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Pass empty options — all defaults should be filled
	client, err := NewClient(ctx, ClientOptions{})
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify defaults were applied
	assert.Equal(t, DefaultClientOptions().RelayAddress, client.opts.RelayAddress)
	assert.Equal(t, DefaultClientOptions().ReconnectInterval, client.opts.ReconnectInterval)
	assert.Equal(t, DefaultClientOptions().MaxReconnectInterval, client.opts.MaxReconnectInterval)
	assert.Equal(t, DefaultClientOptions().BufferSize, client.opts.BufferSize)

	cancel()
	client.Close()
}

func TestClient_SetState(t *testing.T) {
	client := &Client{
		state: StateDisconnected,
	}

	client.setState(StateConnecting)
	assert.Equal(t, StateConnecting, client.State())

	client.setState(StateConnected)
	assert.Equal(t, StateConnected, client.State())
	assert.True(t, client.IsConnected())

	client.setState(StateReconnecting)
	assert.Equal(t, StateReconnecting, client.State())
	assert.False(t, client.IsConnected())
}

func TestClient_CloseIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := NewClient(ctx, ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: time.Hour,
		BufferSize:        5,
		Logger:            zap.NewNop(),
	})
	require.NoError(t, err)

	// Close twice should not panic
	err = client.Close()
	assert.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

func TestClient_ContextCancel_StopsConnectionLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	client, err := NewClient(ctx, ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: time.Hour, // Long interval so we don't reconnect during test
		BufferSize:        5,
		Logger:            zap.NewNop(),
	})
	require.NoError(t, err)

	// Cancel context should cause connectionLoop to exit
	cancel()

	// Close should return promptly (connectionLoop should have exited via context)
	done := make(chan error, 1)
	go func() {
		done <- client.Close()
	}()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return in time after context cancellation")
	}
}

func TestClient_StreamFlows_ContextCancel(t *testing.T) {
	srv := &mockObserverServer{blockCh: make(chan struct{})}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := c.streamFlows(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestClient_StreamFlows_StopChannel(t *testing.T) {
	srv := &mockObserverServer{blockCh: make(chan struct{})}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	// Close stop channel — streamFlows should check it and return
	close(c.stopCh)

	err := c.streamFlows(context.Background())
	// stopCh is checked before Recv(), so streamFlows returns nil immediately.
	assert.NoError(t, err)
}

func TestClient_StreamFlows_TimedContextCancel(t *testing.T) {
	srv := &mockObserverServer{blockCh: make(chan struct{})}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := c.streamFlows(ctx)
	elapsed := time.Since(start)

	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 2*time.Second, "streamFlows should return promptly on context deadline")
}

func TestClient_StreamFlows_ReceivesAndConverts(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	srv := &mockObserverServer{
		flows: []*flowpb.Flow{
			{
				Time:           timestamppb.New(now),
				Uuid:           "test-uuid-1",
				Verdict:        flowpb.Verdict_DROPPED,
				DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
				Source: &flowpb.Endpoint{
					Identity:  100,
					Namespace: "production",
					PodName:   "frontend-abc",
					Labels:    []string{"k8s:app=frontend", "k8s:version=v2"},
					Workloads: []*flowpb.Workload{{Kind: "Deployment", Name: "frontend"}},
				},
				Destination: &flowpb.Endpoint{
					Identity:  200,
					Namespace: "production",
					PodName:   "backend-xyz",
					Labels:    []string{"k8s:app=backend"},
					Workloads: []*flowpb.Workload{{Kind: "Deployment", Name: "backend"}},
				},
				IP: &flowpb.IP{
					Source:      "10.0.1.5",
					Destination: "10.0.2.10",
				},
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_TCP{
						TCP: &flowpb.TCP{
							SourcePort:      45678,
							DestinationPort: 8080,
							Flags:           &flowpb.TCPFlags{SYN: true},
						},
					},
				},
			},
		},
	}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run streamFlows in a goroutine — it will process the flow then return on EOF
	done := make(chan error, 1)
	go func() { done <- c.streamFlows(ctx) }()

	// Read the drop from the channel
	select {
	case drop := <-c.drops:
		assert.Equal(t, "test-uuid-1", drop.TraceID)
		assert.Equal(t, now, drop.Time)
		assert.Equal(t, DropReasonPolicy, drop.DropReason)
		assert.Equal(t, "production", drop.Source.Namespace)
		assert.Equal(t, "frontend-abc", drop.Source.PodName)
		assert.Equal(t, uint32(100), drop.Source.Identity)
		assert.Equal(t, "frontend", drop.Source.Labels["app"])
		assert.Equal(t, "v2", drop.Source.Labels["version"])
		assert.Len(t, drop.Source.Workloads, 1)
		assert.Equal(t, "Deployment", drop.Source.Workloads[0].Kind)
		assert.Equal(t, "production", drop.Destination.Namespace)
		assert.Equal(t, "backend-xyz", drop.Destination.PodName)
		assert.Equal(t, "10.0.1.5", drop.IP.Source)
		assert.Equal(t, "10.0.2.10", drop.IP.Destination)
		assert.Equal(t, ProtocolTCP, drop.L4.Protocol)
		assert.Equal(t, uint32(8080), drop.L4.DestinationPort)
		assert.NotNil(t, drop.L4.TCP)
		assert.True(t, drop.L4.TCP.Flags.SYN)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flow drop")
	}

	// streamFlows should return after EOF
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("streamFlows did not return after EOF")
	}

	// Verify stats
	assert.Equal(t, uint64(1), c.flowDrops)
}

func TestClient_StreamFlows_HandlesNilFlowFields(t *testing.T) {
	// Flow with nil Source, Destination, IP, L4 — should not panic
	srv := &mockObserverServer{
		flows: []*flowpb.Flow{
			{
				Verdict:        flowpb.Verdict_DROPPED,
				DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
				// All optional fields are nil
			},
		},
	}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.streamFlows(ctx) }()

	// Should receive a drop with zero-value fields (no panic)
	select {
	case drop := <-c.drops:
		assert.Equal(t, DropReasonPolicy, drop.DropReason)
		assert.Empty(t, drop.Source.Namespace)
		assert.Empty(t, drop.Destination.Namespace)
		assert.Empty(t, drop.IP.Source)
		assert.Equal(t, Protocol(""), drop.L4.Protocol)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flow drop")
	}

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("streamFlows did not return")
	}
}

func TestClient_StreamFlows_SkipsNonDropVerdict(t *testing.T) {
	srv := &mockObserverServer{
		flows: []*flowpb.Flow{
			{
				Verdict: flowpb.Verdict_FORWARDED,
				Source:  &flowpb.Endpoint{Namespace: "ns", PodName: "pod1"},
			},
			{
				Verdict:        flowpb.Verdict_DROPPED,
				DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
				Source:         &flowpb.Endpoint{Namespace: "ns", PodName: "pod2"},
			},
		},
	}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.streamFlows(ctx) }()

	// Only the dropped flow should appear
	select {
	case drop := <-c.drops:
		assert.Equal(t, "pod2", drop.Source.PodName)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flow drop")
	}

	// Wait for stream to finish
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("streamFlows did not return")
	}

	// Only 1 drop should be recorded
	assert.Equal(t, uint64(1), c.flowDrops)
}

func TestClient_StreamFlows_UDPFlow(t *testing.T) {
	srv := &mockObserverServer{
		flows: []*flowpb.Flow{
			{
				Verdict:        flowpb.Verdict_DROPPED,
				DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_UDP{
						UDP: &flowpb.UDP{
							SourcePort:      12345,
							DestinationPort: 53,
						},
					},
				},
			},
		},
	}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.streamFlows(ctx) }()

	select {
	case drop := <-c.drops:
		assert.Equal(t, ProtocolUDP, drop.L4.Protocol)
		assert.Equal(t, uint32(12345), drop.L4.SourcePort)
		assert.Equal(t, uint32(53), drop.L4.DestinationPort)
		assert.Nil(t, drop.L4.TCP)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flow drop")
	}

	<-done
}

func TestClient_StreamFlows_ICMPv4Flow(t *testing.T) {
	srv := &mockObserverServer{
		flows: []*flowpb.Flow{
			{
				Verdict:        flowpb.Verdict_DROPPED,
				DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_ICMPv4{
						ICMPv4: &flowpb.ICMPv4{Type: 8, Code: 0},
					},
				},
			},
		},
	}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.streamFlows(ctx) }()

	select {
	case drop := <-c.drops:
		assert.Equal(t, ProtocolICMP, drop.L4.Protocol)
		assert.Equal(t, uint32(0), drop.L4.SourcePort)
		assert.Equal(t, uint32(0), drop.L4.DestinationPort)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flow drop")
	}

	<-done
}

func TestClient_StreamFlows_ICMPv6Flow(t *testing.T) {
	srv := &mockObserverServer{
		flows: []*flowpb.Flow{
			{
				Verdict:        flowpb.Verdict_DROPPED,
				DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_ICMPv6{
						ICMPv6: &flowpb.ICMPv6{Type: 128, Code: 0},
					},
				},
			},
		},
	}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.streamFlows(ctx) }()

	select {
	case drop := <-c.drops:
		assert.Equal(t, ProtocolICMP, drop.L4.Protocol)
		assert.Equal(t, uint32(0), drop.L4.SourcePort)
		assert.Equal(t, uint32(0), drop.L4.DestinationPort)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flow drop")
	}

	<-done
}

func TestClient_StreamFlows_UnknownL4Protocol(t *testing.T) {
	srv := &mockObserverServer{
		flows: []*flowpb.Flow{
			{
				Verdict:        flowpb.Verdict_DROPPED,
				DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_SCTP{
						SCTP: &flowpb.SCTP{SourcePort: 1, DestinationPort: 2},
					},
				},
			},
		},
	}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.streamFlows(ctx) }()

	select {
	case drop := <-c.drops:
		assert.Equal(t, ProtocolUnknown, drop.L4.Protocol)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flow drop")
	}

	<-done
}

func TestClient_StreamFlows_TCPWithoutFlags(t *testing.T) {
	srv := &mockObserverServer{
		flows: []*flowpb.Flow{
			{
				Verdict:        flowpb.Verdict_DROPPED,
				DropReasonDesc: flowpb.DropReason_POLICY_DENIED,
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_TCP{
						TCP: &flowpb.TCP{
							SourcePort:      1234,
							DestinationPort: 80,
							// Flags is nil
						},
					},
				},
			},
		},
	}
	conn := newMockObserverConn(t, srv)

	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateConnected,
		conn:   conn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.streamFlows(ctx) }()

	select {
	case drop := <-c.drops:
		assert.Equal(t, ProtocolTCP, drop.L4.Protocol)
		assert.Equal(t, uint32(1234), drop.L4.SourcePort)
		assert.Equal(t, uint32(80), drop.L4.DestinationPort)
		assert.Nil(t, drop.L4.TCP, "TCP info should be nil when flags are absent")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flow drop")
	}

	<-done
}

func TestClient_ConnectionLoop_StopSignal(t *testing.T) {
	// Test that connectionLoop exits on stopCh close
	// connect() will try real gRPC and fail, but the loop should still respect the stop signal
	c := &Client{
		opts: ClientOptions{
			RelayAddress:         "localhost:1", // Invalid port to fail quickly
			ReconnectInterval:    10 * time.Millisecond,
			MaxReconnectInterval: 50 * time.Millisecond,
			BufferSize:           10,
			Logger:               zap.NewNop(),
		},
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateDisconnected,
	}

	c.wg.Add(1)
	go c.connectionLoop(context.Background())

	// Let it try to connect at least once
	time.Sleep(50 * time.Millisecond)

	// Stop it
	close(c.stopCh)

	// Wait with a timeout to prevent test hangs
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("connectionLoop did not exit after stop signal")
	}

	// Drops channel should be closed (connectionLoop defers close(c.drops))
	_, open := <-c.drops
	assert.False(t, open, "drops channel should be closed after connectionLoop exits")
}

func TestClient_ConnectionLoop_ContextCancel(t *testing.T) {
	// Test that connectionLoop exits when context is cancelled
	c := &Client{
		opts: ClientOptions{
			RelayAddress:         "localhost:1",
			ReconnectInterval:    10 * time.Millisecond,
			MaxReconnectInterval: 50 * time.Millisecond,
			BufferSize:           10,
			Logger:               zap.NewNop(),
		},
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateDisconnected,
	}

	ctx, cancel := context.WithCancel(context.Background())

	c.wg.Add(1)
	go c.connectionLoop(ctx)

	// Let it try to connect at least once
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait with a timeout to prevent test hangs
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("connectionLoop did not exit after context cancellation")
	}

	// Drops channel should be closed
	_, open := <-c.drops
	assert.False(t, open, "drops channel should be closed after connectionLoop exits")
}

func TestClient_ConnectionLoop_StateTransitions(t *testing.T) {
	// Test that connectionLoop sets state to Connecting on entry
	// grpc.DialContext is lazy, so connect() will succeed even for invalid addresses.
	// After connect() succeeds, the loop calls streamFlows() which blocks until stop.
	// We verify state transitions by checking state after a brief delay.
	c := &Client{
		opts: ClientOptions{
			RelayAddress:         "localhost:1",
			ReconnectInterval:    10 * time.Millisecond,
			MaxReconnectInterval: 50 * time.Millisecond,
			BufferSize:           10,
			Logger:               zap.NewNop(),
		},
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateDisconnected,
	}

	c.wg.Add(1)
	go c.connectionLoop(context.Background())

	// Let the loop start and connect (lazy dial succeeds immediately)
	time.Sleep(100 * time.Millisecond)

	// Since gRPC dial is lazy and succeeds, the loop should have progressed
	// to Connected state and be waiting in streamFlows
	state := c.State()
	assert.True(t, state == StateConnected || state == StateConnecting || state == StateReconnecting,
		"expected a valid state, got %s", state)

	close(c.stopCh)
	c.wg.Wait()
}

func TestClient_Close_WithNilConn(t *testing.T) {
	// Directly test Close when conn is nil (covers the nil-conn path)
	c := &Client{
		opts:   DefaultClientOptions(),
		logger: zap.NewNop().Named("hubble"),
		drops:  make(chan FlowDrop, 10),
		stopCh: make(chan struct{}),
		state:  StateDisconnected,
		conn:   nil, // Explicitly nil
	}

	// Need a goroutine on wg to match what connectionLoop would do
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		<-c.stopCh
		close(c.drops)
	}()

	err := c.Close()
	assert.NoError(t, err, "Close with nil conn should return nil")
}

func TestClient_recordFlowDrop_ChannelFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := NewClient(ctx, ClientOptions{
		RelayAddress:      "localhost:4245",
		ReconnectInterval: time.Hour,
		BufferSize:        2, // Small buffer
		Logger:            zap.NewNop(),
	})
	require.NoError(t, err)
	defer client.Close()

	drop := NewFlowDropBuilder().
		WithSource("ns", "pod1", nil).
		WithDestination("ns", "pod2", nil).
		Build()

	// Fill the buffer
	client.recordFlowDrop(drop)
	client.recordFlowDrop(drop)

	// This should not block, just drop the event
	client.recordFlowDrop(drop)

	// Only 2 drops should be recorded (buffer size)
	// The third one should be dropped
	stats := client.Stats()
	assert.Equal(t, uint64(2), stats.FlowDrops)
}
