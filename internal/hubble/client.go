package hubble

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// ClientOptions configures the Hubble client.
type ClientOptions struct {
	// RelayAddress is the gRPC address of Hubble Relay (e.g., "hubble-relay.kube-system.svc:4245")
	RelayAddress string

	// ReconnectInterval is the base interval between reconnection attempts
	ReconnectInterval time.Duration

	// MaxReconnectInterval is the maximum interval between reconnection attempts
	MaxReconnectInterval time.Duration

	// BufferSize is the size of the flow drop channel buffer
	BufferSize int

	// Logger for the client
	Logger *zap.Logger
}

// DefaultClientOptions returns default options for the Hubble client.
func DefaultClientOptions() ClientOptions {
	return ClientOptions{
		RelayAddress:         "hubble-relay.kube-system.svc.cluster.local:4245",
		ReconnectInterval:    time.Second,
		MaxReconnectInterval: time.Minute,
		BufferSize:           1000,
		Logger:               zap.NewNop(),
	}
}

// Client connects to Hubble Relay and streams flow drop events.
type Client struct {
	opts   ClientOptions
	logger *zap.Logger

	conn    *grpc.ClientConn
	state   ConnectionState
	stateMu sync.RWMutex

	drops    chan FlowDrop
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// Metrics
	reconnects uint64
	flowDrops  uint64
}

// NewClient creates a new Hubble client and starts the connection.
func NewClient(ctx context.Context, opts ClientOptions) (*Client, error) {
	if opts.Logger == nil {
		opts.Logger = zap.NewNop()
	}
	if opts.RelayAddress == "" {
		opts.RelayAddress = DefaultClientOptions().RelayAddress
	}
	if opts.ReconnectInterval == 0 {
		opts.ReconnectInterval = DefaultClientOptions().ReconnectInterval
	}
	if opts.MaxReconnectInterval == 0 {
		opts.MaxReconnectInterval = DefaultClientOptions().MaxReconnectInterval
	}
	if opts.BufferSize == 0 {
		opts.BufferSize = DefaultClientOptions().BufferSize
	}

	c := &Client{
		opts:   opts,
		logger: opts.Logger.Named("hubble"),
		drops:  make(chan FlowDrop, opts.BufferSize),
		stopCh: make(chan struct{}),
		state:  StateDisconnected,
	}

	// Start the connection loop
	c.wg.Add(1)
	go c.connectionLoop(ctx)

	return c, nil
}

// DroppedFlows returns a channel of flow drop events.
// The channel is closed when the client is stopped.
func (c *Client) DroppedFlows() <-chan FlowDrop {
	return c.drops
}

// State returns the current connection state.
func (c *Client) State() ConnectionState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

// IsConnected returns true if currently connected to Hubble Relay.
func (c *Client) IsConnected() bool {
	return c.State() == StateConnected
}

// Stats returns client statistics.
func (c *Client) Stats() ClientStats {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return ClientStats{
		State:      c.state,
		Reconnects: c.reconnects,
		FlowDrops:  c.flowDrops,
	}
}

// ClientStats contains client statistics.
type ClientStats struct {
	State      ConnectionState
	Reconnects uint64
	FlowDrops  uint64
}

// Close stops the client and releases resources.
// The connection is closed by connectionLoop before it exits,
// so Close only needs to signal stop and wait.
func (c *Client) Close() error {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	c.wg.Wait()
	return nil
}

// connectionLoop manages the connection to Hubble Relay with reconnection.
func (c *Client) connectionLoop(ctx context.Context) {
	defer c.wg.Done()
	defer close(c.drops)

	reconnectInterval := c.opts.ReconnectInterval

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("context cancelled, stopping connection loop")
			return
		case <-c.stopCh:
			c.logger.Info("stop signal received, stopping connection loop")
			return
		default:
		}

		c.setState(StateConnecting)

		err := c.connect(ctx)
		if err != nil {
			c.logger.Warn("failed to connect to Hubble Relay",
				zap.Error(err),
				zap.Duration("retry_in", reconnectInterval))

			// Exponential backoff
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-time.After(reconnectInterval):
				reconnectInterval = c.nextReconnectInterval(reconnectInterval)
			}
			continue
		}

		// Reset reconnect interval on successful connection
		reconnectInterval = c.opts.ReconnectInterval

		c.setState(StateConnected)
		c.logger.Info("connected to Hubble Relay", zap.String("address", c.opts.RelayAddress))

		// Stream flows until disconnected
		err = c.streamFlows(ctx)
		if err != nil {
			c.logger.Warn("flow stream disconnected", zap.Error(err))
		}

		if c.conn != nil {
			_ = c.conn.Close()
			c.conn = nil
		}

		c.stateMu.Lock()
		c.state = StateReconnecting
		c.reconnects++
		c.stateMu.Unlock()
	}
}

// connect establishes a gRPC connection to Hubble Relay.
func (c *Client) connect(_ context.Context) error {
	conn, err := grpc.NewClient(c.opts.RelayAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to create Hubble Relay client: %w", err)
	}

	c.conn = conn
	return nil
}

// streamFlows streams dropped flow events from Hubble Relay via the Observer gRPC API.
func (c *Client) streamFlows(ctx context.Context) error {
	observer := observerpb.NewObserverClient(c.conn)

	req := &observerpb.GetFlowsRequest{
		Follow: true,
		Whitelist: []*flowpb.FlowFilter{
			{Verdict: []flowpb.Verdict{flowpb.Verdict_DROPPED}},
		},
	}

	stream, err := observer.GetFlows(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("GetFlows: %w", err)
	}

	c.logger.Info("streaming dropped flows from Hubble Relay")

	for {
		select {
		case <-c.stopCh:
			return nil
		default:
		}

		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("stream recv: %w", err)
		}

		f := resp.GetFlow()
		if f == nil {
			continue
		}

		drop, ok := convertFlow(f)
		if !ok {
			continue
		}

		c.recordFlowDrop(drop)
	}
}

// convertFlow converts a Cilium Flow proto to an internal FlowDrop.
// Returns false if the flow cannot be converted (e.g. not a drop).
func convertFlow(f *flowpb.Flow) (FlowDrop, bool) {
	if f.GetVerdict() != flowpb.Verdict_DROPPED {
		return FlowDrop{}, false
	}

	drop := FlowDrop{
		TraceID:    f.GetUuid(),
		DropReason: ParseDropReason(int32(f.GetDropReasonDesc())),
	}

	if t := f.GetTime(); t != nil {
		drop.Time = t.AsTime()
	} else {
		drop.Time = time.Now()
	}

	if src := f.GetSource(); src != nil {
		drop.Source = Endpoint{
			Identity:  src.GetIdentity(),
			Namespace: src.GetNamespace(),
			PodName:   src.GetPodName(),
			Labels:    parseLabels(src.GetLabels()),
		}
		for _, w := range src.GetWorkloads() {
			if w != nil {
				drop.Source.Workloads = append(drop.Source.Workloads, WorkloadRef{
					Kind: w.GetKind(),
					Name: w.GetName(),
				})
			}
		}
	}

	if dst := f.GetDestination(); dst != nil {
		drop.Destination = Endpoint{
			Identity:  dst.GetIdentity(),
			Namespace: dst.GetNamespace(),
			PodName:   dst.GetPodName(),
			Labels:    parseLabels(dst.GetLabels()),
		}
		for _, w := range dst.GetWorkloads() {
			if w != nil {
				drop.Destination.Workloads = append(drop.Destination.Workloads, WorkloadRef{
					Kind: w.GetKind(),
					Name: w.GetName(),
				})
			}
		}
	}

	if ip := f.GetIP(); ip != nil {
		drop.IP = IPInfo{
			Source:      ip.GetSource(),
			Destination: ip.GetDestination(),
		}
	}

	if l4 := f.GetL4(); l4 != nil {
		switch {
		case l4.GetTCP() != nil:
			tcp := l4.GetTCP()
			drop.L4 = L4Info{
				Protocol:        ProtocolTCP,
				SourcePort:      tcp.GetSourcePort(),
				DestinationPort: tcp.GetDestinationPort(),
			}
			if flags := tcp.GetFlags(); flags != nil {
				drop.L4.TCP = &TCPInfo{
					Flags: TCPFlags{
						SYN: flags.GetSYN(),
						ACK: flags.GetACK(),
						FIN: flags.GetFIN(),
						RST: flags.GetRST(),
					},
				}
			}
		case l4.GetUDP() != nil:
			udp := l4.GetUDP()
			drop.L4 = L4Info{
				Protocol:        ProtocolUDP,
				SourcePort:      udp.GetSourcePort(),
				DestinationPort: udp.GetDestinationPort(),
			}
		case l4.GetICMPv4() != nil:
			drop.L4 = L4Info{Protocol: ProtocolICMP}
		case l4.GetICMPv6() != nil:
			drop.L4 = L4Info{Protocol: ProtocolICMP}
		default:
			drop.L4 = L4Info{Protocol: ProtocolUnknown}
		}
	}

	return drop, true
}

// setState updates the connection state.
func (c *Client) setState(state ConnectionState) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.state = state
}

// nextReconnectInterval calculates the next reconnect interval with exponential backoff.
func (c *Client) nextReconnectInterval(current time.Duration) time.Duration {
	next := current * 2
	if next > c.opts.MaxReconnectInterval {
		return c.opts.MaxReconnectInterval
	}
	return next
}

// recordFlowDrop records a flow drop event.
func (c *Client) recordFlowDrop(drop FlowDrop) {
	select {
	case c.drops <- drop:
		c.stateMu.Lock()
		c.flowDrops++
		c.stateMu.Unlock()
	default:
		c.logger.Warn("flow drop channel full, dropping event",
			zap.String("source", drop.Source.PodName),
			zap.String("dest", drop.Destination.PodName))
	}
}
