package server

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/awcullen/opcua"

	"github.com/gammazero/workerpool"
)

type key string

const (
	// SessionKey stores the current session in context
	SessionKey key = "opcua-session"
	// documents the version of binary protocol that this library supports.
	protocolVersion uint32 = 0
	// the default size of the send and recieve buffers.
	defaultBufferSize uint32 = 64 * 1024
	// the limit on the size of messages that may be accepted.
	defaultMaxMessageSize uint32 = 16 * 1024 * 1024
	// defaultMaxChunkCount sets the limit on the number of message chunks that may be accepted.
	defaultMaxChunkCount uint32 = 4 * 1024
	// the default number of milliseconds that a session may be unused before being closed by the server. (2 min)
	defaultSessionTimeout float64 = 120 * 1000
	// the default number of sessions that may be active.
	defaultMaxSessionCount uint32 = 0
	// the default number of subscriptions that may be active.
	defaultMaxSubscriptionCount uint32 = 0
	// the default number of worker threads that may be created.
	defaultMaxWorkerThreads int = 4
	// the default number of milliseconds to wait to reregister this server with the discovery server. (30 sec)
	defaultRegistrationInterval float64 = 30 * 1000
	// the length of nonce in bytes.
	nonceLength int = 32
)

// Server implements an OpcUa server for clients.
type Server struct {
	sync.RWMutex
	localDescription                   opcua.ApplicationDescription
	endpoints                          []opcua.EndpointDescription
	sessionTimeout                     float64
	maxSessionCount                    uint32
	maxSubscriptionCount               uint32
	serverCapabilities                 *opcua.ServerCapabilities
	buildInfo                          opcua.BuildInfo
	certPath                           string
	keyPath                            string
	trustedCertsPath                   string
	endpointURL                        string
	suppressCertificateExpired         bool
	suppressCertificateChainIncomplete bool
	receiveBufferSize                  uint32
	sendBufferSize                     uint32
	maxMessageSize                     uint32
	maxChunkCount                      uint32
	maxWorkerThreads                   int
	registrationURL                    string
	registrationInterval               float64
	serverDiagnostics                  bool
	trace                              bool
	applicationCertificate             tls.Certificate
	listeners                          []net.Listener
	closed                             chan struct{}
	closing                            chan struct{}
	stateSemaphore                     chan struct{}
	state                              opcua.ServerState
	secondsTillShutdown                uint32
	shutdownReason                     opcua.LocalizedText
	stateListener                      func(state opcua.ServerState)
	workerpool                         *workerpool.WorkerPool
	channelManager                     *ChannelManager
	sessionManager                     *SessionManager
	subscriptionManager                *SubscriptionManager
	namespaceManager                   *NamespaceManager
	registrationManager                *RegistrationManager
	serverUris                         []string
	startTime                          time.Time
	serverDiagnosticsSummary           *opcua.ServerDiagnosticsSummaryDataType
	useRegisterServer2                 bool
	scheduler                          *Scheduler
	historian                          HistoryReadWriter
	userNameIdentityAuthenticator      UserNameIdentityAuthenticator
	x509IdentityAuthenticator          X509IdentityAuthenticator
	issuedIdentityAuthenticator        IssuedIdentityAuthenticator
	rolesProvider                      RolesProvider
	rolePermissions                    []opcua.RolePermissionType
}

// New initializes a new instance of the UaTcpServer.
func New(localDescription opcua.ApplicationDescription, certPath, keyPath, endpointURL string, options ...Option) (*Server, error) {
	srv := &Server{
		localDescription:                   localDescription,
		certPath:                           certPath,
		keyPath:                            keyPath,
		endpointURL:                        endpointURL,
		sessionTimeout:                     defaultSessionTimeout,
		maxSessionCount:                    defaultMaxSessionCount,
		maxSubscriptionCount:               defaultMaxSubscriptionCount,
		serverCapabilities:                 opcua.NewServerCapabilities(),
		buildInfo:                          opcua.BuildInfo{},
		suppressCertificateExpired:         false,
		suppressCertificateChainIncomplete: false,
		receiveBufferSize:                  defaultBufferSize,
		sendBufferSize:                     defaultBufferSize,
		maxMessageSize:                     defaultMaxMessageSize,
		maxChunkCount:                      defaultMaxChunkCount,
		maxWorkerThreads:                   defaultMaxWorkerThreads,
		registrationURL:                    "opc.tcp://127.0.0.1:4840",
		registrationInterval:               defaultRegistrationInterval,
		serverDiagnostics:                  true,
		trace:                              false,
		closed:                             make(chan struct{}),
		closing:                            make(chan struct{}),
		stateSemaphore:                     make(chan struct{}, 1),
		listeners:                          make([]net.Listener, 0, 3),
		serverUris:                         []string{localDescription.ApplicationURI},
		state:                              opcua.ServerStateUnknown,
		startTime:                          time.Now(),
		serverDiagnosticsSummary:           &opcua.ServerDiagnosticsSummaryDataType{},
		useRegisterServer2:                 true,
		rolePermissions:                    DefaultRolePermissions,
	}

	// apply each option to the default
	for _, opt := range options {
		if err := opt(srv); err != nil {
			return nil, err
		}
	}

	srv.workerpool = workerpool.New(srv.maxWorkerThreads)
	srv.channelManager = NewChannelManager(srv)
	srv.sessionManager = NewSessionManager(srv)
	srv.subscriptionManager = NewSubscriptionManager(srv)
	srv.namespaceManager = NewNamespaceManager(srv)
	srv.registrationManager = NewRegistrationManager(srv)
	srv.scheduler = NewScheduler(srv)

	var err error
	if srv.applicationCertificate, err = tls.LoadX509KeyPair(srv.certPath, srv.keyPath); err != nil {
		log.Printf("Error loading x509 key pair. %s\n", err)
		return nil, err
	}

	if err := srv.initializeNamespace(); err != nil {
		log.Printf("Error initializing namespace. %s\n", err)
		return nil, err
	}
	return srv, nil
}

// LocalDescription gets the application description.
func (srv *Server) LocalDescription() opcua.ApplicationDescription {
	srv.RLock()
	defer srv.RUnlock()
	return srv.localDescription
}

// LocalCertificate gets the certificate for the local application.
func (srv *Server) LocalCertificate() []byte {
	srv.RLock()
	defer srv.RUnlock()
	return srv.applicationCertificate.Certificate[0]
}

// LocalPrivateKey gets the local private key.
func (srv *Server) LocalPrivateKey() *rsa.PrivateKey {
	srv.RLock()
	defer srv.RUnlock()
	return srv.applicationCertificate.PrivateKey.(*rsa.PrivateKey)
}

// EndpointURL gets the endpoint url.
func (srv *Server) EndpointURL() string {
	srv.RLock()
	defer srv.RUnlock()
	return srv.endpointURL
}

// Endpoints gets the endpoint descriptions.
func (srv *Server) Endpoints() []opcua.EndpointDescription {
	srv.RLock()
	defer srv.RUnlock()
	if srv.endpoints == nil {
		srv.endpoints = srv.buildEndpointDescriptions()
	}
	return srv.endpoints
}

// Closing gets a channel that broadcasts the closing of the server.
func (srv *Server) Closing() <-chan struct{} {
	srv.RLock()
	defer srv.RUnlock()
	return srv.closing
}

// State gets the ServerState.
func (srv *Server) State() opcua.ServerState {
	srv.RLock()
	defer srv.RUnlock()
	return srv.state
}

func (srv *Server) setState(value opcua.ServerState) {
	srv.Lock()
	srv.state = value
	listener := srv.stateListener
	srv.Unlock()
	if listener != nil {
		listener(srv.state)
	}
}

// SetStateListener sets a func that listens for change of ServerState.
func (srv *Server) SetStateListener(listener func(state opcua.ServerState)) {
	srv.Lock()
	defer srv.Unlock()
	srv.stateListener = listener
}

// NamespaceUris gets the namespace uris.
func (srv *Server) NamespaceUris() []string {
	srv.RLock()
	defer srv.RUnlock()
	return srv.namespaceManager.NamespaceUris()
}

// ServerUris gets the server uris.
func (srv *Server) ServerUris() []string {
	srv.RLock()
	defer srv.RUnlock()
	return srv.serverUris
}

// RolePermissions gets the RolePermissions.
func (srv *Server) RolePermissions() []opcua.RolePermissionType {
	return srv.rolePermissions
}

// WorkerPool gets a pool of workers.
func (srv *Server) WorkerPool() *workerpool.WorkerPool {
	srv.RLock()
	defer srv.RUnlock()
	return srv.workerpool
}

// ChannelManager gets the secure channel manager.
func (srv *Server) ChannelManager() *ChannelManager {
	srv.RLock()
	defer srv.RUnlock()
	return srv.channelManager
}

// SessionManager gets the session manager.
func (srv *Server) SessionManager() *SessionManager {
	srv.RLock()
	defer srv.RUnlock()
	return srv.sessionManager
}

// NamespaceManager gets the namespace manager.
func (srv *Server) NamespaceManager() *NamespaceManager {
	srv.RLock()
	defer srv.RUnlock()
	return srv.namespaceManager
}

// SubscriptionManager gets the subscription Manager.
func (srv *Server) SubscriptionManager() *SubscriptionManager {
	srv.RLock()
	defer srv.RUnlock()
	return srv.subscriptionManager
}

// Scheduler gets the polling scheduler.
func (srv *Server) Scheduler() *Scheduler {
	srv.RLock()
	defer srv.RUnlock()
	return srv.scheduler
}

// Historian gets the HistoryReadWriter.
func (srv *Server) Historian() HistoryReadWriter {
	srv.RLock()
	defer srv.RUnlock()
	return srv.historian
}

// MaxSessionCount gets the maximum number of sessions.
func (srv *Server) MaxSessionCount() uint32 {
	srv.RLock()
	defer srv.RUnlock()
	return srv.maxSessionCount
}

// MaxSubscriptionCount gets the maximum number of subscriptions.
func (srv *Server) MaxSubscriptionCount() uint32 {
	srv.RLock()
	defer srv.RUnlock()
	return srv.maxSubscriptionCount
}

// ServerCapabilities gets the capabilities of the server.
func (srv *Server) ServerCapabilities() *opcua.ServerCapabilities {
	srv.RLock()
	defer srv.RUnlock()
	return srv.serverCapabilities
}

// ListenAndServe listens on the EndpointURL for incoming connections and then
// handles service requests.
// ListenAndServe always returns a non-nil error. After Shutdown or Close,
// the returned error is BadServerHalted.
func (srv *Server) ListenAndServe() error {
	srv.stateSemaphore <- struct{}{}
	if srv.state != opcua.ServerStateUnknown {
		<-srv.stateSemaphore
		return opcua.BadInternalError
	}
	baseURL, err := url.Parse(srv.endpointURL)
	if err != nil {
		// log.Printf("Error opening secure channel listener. %s\n", err.Error())
		<-srv.stateSemaphore
		return opcua.BadTCPEndpointURLInvalid
	}
	l, err := net.Listen("tcp", ":"+baseURL.Port())
	if err != nil {
		// log.Printf("Error opening secure channel listener. %s\n", err.Error())
		<-srv.stateSemaphore
		return opcua.BadResourceUnavailable
	}
	srv.listeners = append(srv.listeners, l)
	srv.setState(opcua.ServerStateRunning)
	<-srv.stateSemaphore

	return srv.serve(l)
}

// Close server.
func (srv *Server) Close() error {
	srv.stateSemaphore <- struct{}{}
	if srv.state != opcua.ServerStateRunning {
		<-srv.stateSemaphore
		return opcua.BadInternalError
	}

	// allow for clients to stop gracefully
	srv.setState(opcua.ServerStateShutdown)
	srv.shutdownReason = opcua.NewLocalizedText("Closing", "")
	for i := 3; i > 0; i-- {
		srv.secondsTillShutdown = uint32(i)
		time.Sleep(time.Second)
	}
	srv.secondsTillShutdown = uint32(0)

	// close subscriptions
	close(srv.closing)

	// allow managers to close
	srv.registrationManager.Wait()

	// close listeners
	for _, l := range srv.listeners {
		err := l.Close()
		if err != nil {
			log.Printf("Error closing secure channel listener: %s\n", err.Error())
		}
	}

	// stop workers.
	srv.workerpool.StopWait()

	// close channels
	close(srv.closed)

	<-srv.stateSemaphore
	return nil
}

// Abort the server.
func (srv *Server) Abort() error {
	srv.stateSemaphore <- struct{}{}
	if srv.state != opcua.ServerStateRunning {
		<-srv.stateSemaphore
		return opcua.BadInternalError
	}

	srv.setState(opcua.ServerStateFailed)

	// close subscriptions
	close(srv.closing)

	// close listeners
	for _, l := range srv.listeners {
		err := l.Close()
		if err != nil {
			log.Printf("Error closing secure channel listener: %s\n", err.Error())
		}
	}

	// stop workers but don't wait.
	srv.workerpool.Stop()

	// close channels
	close(srv.closed)

	<-srv.stateSemaphore
	return nil
}

func (srv *Server) serve(l net.Listener) error {
	var delay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if max := 1 * time.Second; delay > max {
					delay = max
				}
				time.Sleep(delay)
				continue
			}
			select {
			case <-srv.closing:
				return opcua.BadServerHalted
			default:
				return opcua.BadTCPInternalError
			}
		}
		delay = 0
		ch := newServerSecureChannel(srv, conn, srv.receiveBufferSize, srv.sendBufferSize, srv.maxMessageSize, srv.maxChunkCount, srv.trace)
		go func(ch *serverSecureChannel) {
			err := ch.Open()
			if err != nil {
				if reason, ok := err.(opcua.StatusCode); ok {
					ch.Abort(reason, reason.Error())
					return
				}
				ch.Abort(opcua.BadSecureChannelClosed, err.Error())
				return
			}
			srv.channelManager.Add(ch)
		}(ch)
	}
}

func (srv *Server) handleCloseSecureChannel(ch *serverSecureChannel, requestid uint32, req *opcua.CloseSecureChannelRequest) error {
	srv.ChannelManager().Delete(ch)
	ch.Close()
	return nil
}

func (srv *Server) initializeNamespace() error {
	nm := srv.NamespaceManager()
	if err := nm.LoadNodeSetFromBuffer([]byte(nodeset104)); err != nil {
		return err
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerAuditing); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindNode(opcua.MethodIDServerRequestServerStateChange); ok {
		nm.DeleteNode(n, true)
	}
	if n, ok := nm.FindNode(opcua.MethodIDServerSetSubscriptionDurable); ok {
		nm.DeleteNode(n, true)
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServiceLevel); ok {
		n.SetValue(opcua.NewDataValue(byte(255), 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerRedundancyRedundancySupport); ok {
		n.SetValue(opcua.NewDataValue(int32(0), 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindNode(opcua.VariableIDServerServerRedundancyCurrentServerID); ok {
		nm.DeleteNode(n, false)
	}
	if n, ok := nm.FindNode(opcua.VariableIDServerServerRedundancyRedundantServerArray); ok {
		nm.DeleteNode(n, true)
	}
	if n, ok := nm.FindNode(opcua.VariableIDServerServerRedundancyServerNetworkGroups); ok {
		nm.DeleteNode(n, true)
	}
	if n, ok := nm.FindNode(opcua.VariableIDServerServerRedundancyServerURIArray); ok {
		nm.DeleteNode(n, true)
	}

	if n, ok := nm.FindVariable(opcua.VariableIDServerNamespaceArray); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.NamespaceUris(), 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerArray); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.ServerUris(), 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatus); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(
				opcua.ServerStatusDataType{
					StartTime:           srv.startTime,
					CurrentTime:         time.Now(),
					State:               srv.state,
					BuildInfo:           srv.buildInfo,
					ShutdownReason:      srv.shutdownReason,
					SecondsTillShutdown: srv.secondsTillShutdown,
				}, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusState); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(int32(srv.State()), 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusCurrentTime); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(time.Now(), 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusSecondsTillShutdown); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.secondsTillShutdown, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusShutdownReason); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.shutdownReason, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusStartTime); ok {
		n.SetValue(opcua.NewDataValue(srv.startTime, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusBuildInfo); ok {
		n.SetValue(opcua.NewDataValue(srv.buildInfo, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusBuildInfoProductURI); ok {
		n.SetValue(opcua.NewDataValue(srv.buildInfo.ProductURI, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusBuildInfoManufacturerName); ok {
		n.SetValue(opcua.NewDataValue(srv.buildInfo.ManufacturerName, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusBuildInfoProductName); ok {
		n.SetValue(opcua.NewDataValue(srv.buildInfo.ProductName, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusBuildInfoSoftwareVersion); ok {
		n.SetValue(opcua.NewDataValue(srv.buildInfo.SoftwareVersion, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusBuildInfoBuildNumber); ok {
		n.SetValue(opcua.NewDataValue(srv.buildInfo.BuildNumber, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerStatusBuildInfoBuildDate); ok {
		n.SetValue(opcua.NewDataValue(srv.buildInfo.BuildDate, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesLocaleIDArray); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.LocaleIDArray, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesMaxStringLength); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.MaxStringLength, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesMaxArrayLength); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.MaxArrayLength, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesMaxByteStringLength); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.MaxByteStringLength, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesMaxBrowseContinuationPoints); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.MaxBrowseContinuationPoints, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesMaxHistoryContinuationPoints); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.MaxHistoryContinuationPoints, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesMaxQueryContinuationPoints); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.MaxQueryContinuationPoints, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesMinSupportedSampleRate); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.MinSupportedSampleRate, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesServerProfileArray); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.ServerProfileArray, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesAccessHistoryDataCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesInsertDataCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesReplaceDataCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesUpdateDataCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesDeleteRawCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesDeleteAtTimeCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesAccessHistoryEventsCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesMaxReturnDataValues); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesMaxReturnEventValues); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesInsertAnnotationCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesInsertEventCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesReplaceEventCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDHistoryServerCapabilitiesUpdateEventCapability); ok {
		n.SetValue(opcua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxMonitoredItemsPerCall); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxMonitoredItemsPerCall, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerBrowse); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerBrowse, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryReadData); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerHistoryReadData, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryReadEvents); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerHistoryReadEvents, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryUpdateData); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerHistoryUpdateData, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryUpdateEvents); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerHistoryUpdateEvents, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerMethodCall); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerMethodCall, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerNodeManagement); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerNodeManagement, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerRead); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerRead, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerRegisterNodes); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerRegisterNodes, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerTranslateBrowsePathsToNodeIDs); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerTranslateBrowsePathsToNodeIds, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerWrite); ok {
		n.SetValue(opcua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerWrite, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindObject(opcua.ObjectIDServerServerCapabilitiesModellingRules); ok {
		if mandatory, ok := nm.FindObject(opcua.ObjectIDModellingRuleMandatory); ok {
			mandatory.SetReferences(append(mandatory.References(), opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(n.NodeID()))))
			n.SetReferences(append(n.References(), opcua.NewReference(opcua.ReferenceTypeIDHasComponent, false, opcua.NewExpandedNodeID(mandatory.NodeID()))))
		}
		if mandatoryPlaceholder, ok := nm.FindObject(opcua.ObjectIDModellingRuleMandatoryPlaceholder); ok {
			mandatoryPlaceholder.SetReferences(append(mandatoryPlaceholder.References(), opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(n.NodeID()))))
			n.SetReferences(append(n.References(), opcua.NewReference(opcua.ReferenceTypeIDHasComponent, false, opcua.NewExpandedNodeID(mandatoryPlaceholder.NodeID()))))
		}
		if optional, ok := nm.FindObject(opcua.ObjectIDModellingRuleOptional); ok {
			optional.SetReferences(append(optional.References(), opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(n.NodeID()))))
			n.SetReferences(append(n.References(), opcua.NewReference(opcua.ReferenceTypeIDHasComponent, false, opcua.NewExpandedNodeID(optional.NodeID()))))
		}
		if optionalPlaceholder, ok := nm.FindObject(opcua.ObjectIDModellingRuleOptionalPlaceholder); ok {
			optionalPlaceholder.SetReferences(append(optionalPlaceholder.References(), opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(n.NodeID()))))
			n.SetReferences(append(n.References(), opcua.NewReference(opcua.ReferenceTypeIDHasComponent, false, opcua.NewExpandedNodeID(optionalPlaceholder.NodeID()))))
		}
	}
	if nr, ok := nm.FindVariable(opcua.VariableIDModellingRuleMandatoryNamingRule); ok {
		nr.SetValue(opcua.NewDataValue(int32(1), 0, time.Now(), 0, time.Now(), 0))
	}
	if nr, ok := nm.FindVariable(opcua.VariableIDModellingRuleMandatoryPlaceholderNamingRule); ok {
		nr.SetValue(opcua.NewDataValue(int32(1), 0, time.Now(), 0, time.Now(), 0))
	}
	if nr, ok := nm.FindVariable(opcua.VariableIDModellingRuleOptionalNamingRule); ok {
		nr.SetValue(opcua.NewDataValue(int32(2), 0, time.Now(), 0, time.Now(), 0))
	}
	if nr, ok := nm.FindVariable(opcua.VariableIDModellingRuleOptionalPlaceholderNamingRule); ok {
		nr.SetValue(opcua.NewDataValue(int32(2), 0, time.Now(), 0, time.Now(), 0))
	}

	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsEnabledFlag); ok {
		n.SetValue(opcua.NewDataValue(srv.serverDiagnostics, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummary); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryCumulatedSessionCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.CumulatedSessionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryCumulatedSubscriptionCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.CumulatedSubscriptionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryCurrentSessionCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.CurrentSessionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryCurrentSubscriptionCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.CurrentSubscriptionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryServerViewCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.ServerViewCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummarySecurityRejectedSessionCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.SecurityRejectedSessionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummarySessionAbortCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.SessionAbortCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryPublishingIntervalCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.PublishingIntervalCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummarySecurityRejectedRequestsCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.SecurityRejectedRequestsCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryRejectedRequestsCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.RejectedRequestsCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryRejectedSessionCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.RejectedSessionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsServerDiagnosticsSummarySessionTimeoutCount); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			return opcua.NewDataValue(srv.serverDiagnosticsSummary.SessionTimeoutCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(opcua.VariableIDServerServerDiagnosticsSubscriptionDiagnosticsArray); ok {
		n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
			if !srv.serverDiagnostics {
				return opcua.NewDataValue(nil, 0, time.Now(), 0, time.Now(), 0)
			}
			a := make([]opcua.ExtensionObject, 0, 16)
			for _, s := range srv.SubscriptionManager().subscriptionsByID {
				s.RLock()
				e := opcua.SubscriptionDiagnosticsDataType{
					SessionID:                  s.sessionId,
					SubscriptionID:             s.id,
					Priority:                   s.priority,
					PublishingInterval:         s.publishingInterval,
					MaxKeepAliveCount:          s.maxKeepAliveCount,
					MaxLifetimeCount:           s.lifetimeCount,
					MaxNotificationsPerPublish: s.maxNotificationsPerPublish,
					PublishingEnabled:          s.publishingEnabled,
					ModifyCount:                s.modifyCount,
					// EnableCount:                  uint32(0),
					// DisableCount:                 uint32(0),
					RepublishRequestCount:        s.republishRequestCount,
					RepublishMessageRequestCount: s.republishMessageRequestCount,
					RepublishMessageCount:        s.republishMessageCount,
					// TransferRequestCount:         uint32(0),
					// TransferredToAltClientCount:  uint32(0),
					// TransferredToSameClientCount: uint32(0),
					PublishRequestCount:          s.publishRequestCount,
					DataChangeNotificationsCount: s.dataChangeNotificationsCount,
					EventNotificationsCount:      s.eventNotificationsCount,
					NotificationsCount:           s.notificationsCount,
					LatePublishRequestCount:      s.latePublishRequestCount,
					CurrentKeepAliveCount:        s.keepAliveCounter,
					CurrentLifetimeCount:         s.lifetimeCounter,
					UnacknowledgedMessageCount:   s.unacknowledgedMessageCount,
					// DiscardedMessageCount:        uint32(0),
					MonitoredItemCount:           s.monitoredItemCount,
					DisabledMonitoredItemCount:   s.disabledMonitoredItemCount,
					MonitoringQueueOverflowCount: s.monitoringQueueOverflowCount,
					NextSequenceNumber:           s.seqNum,
					// EventQueueOverFlowCount:      uint32(0),
				}
				s.RUnlock()
				a = append(a, e)
			}
			return opcua.NewDataValue(a, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindNode(opcua.VariableIDServerServerDiagnosticsSamplingIntervalDiagnosticsArray); ok {
		nm.DeleteNode(n, true)
	}

	if n, ok := nm.FindMethod(opcua.MethodIDServerGetMonitoredItems); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req opcua.CallMethodRequest) opcua.CallMethodResult {
			if len(req.InputArguments) < 1 {
				return opcua.CallMethodResult{StatusCode: opcua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 1 {
				return opcua.CallMethodResult{StatusCode: opcua.BadTooManyArguments}
			}
			opResult := opcua.Good
			argsResults := make([]opcua.StatusCode, 1)
			subscriptionID, ok := req.InputArguments[0].(uint32)
			if !ok {
				opResult = opcua.BadInvalidArgument
				argsResults[0] = opcua.BadTypeMismatch
			}
			if opResult == opcua.BadInvalidArgument {
				return opcua.CallMethodResult{StatusCode: opResult, InputArgumentResults: argsResults}
			}
			sub, ok := srv.SubscriptionManager().Get(subscriptionID)
			if !ok {
				return opcua.CallMethodResult{StatusCode: opcua.BadSubscriptionIDInvalid}
			}
			session, ok := ctx.Value(SessionKey).(*Session)
			if !ok || sub.session != session {
				return opcua.CallMethodResult{StatusCode: opcua.BadUserAccessDenied}
			}
			svrHandles := []uint32{}
			cliHandles := []uint32{}
			for _, item := range sub.Items() {
				svrHandles = append(svrHandles, item.id)
				cliHandles = append(cliHandles, item.clientHandle)
			}
			return opcua.CallMethodResult{OutputArguments: []opcua.Variant{svrHandles, cliHandles}}
		})
	}

	if n, ok := nm.FindMethod(opcua.MethodIDServerGetMonitoredItems); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req opcua.CallMethodRequest) opcua.CallMethodResult {
			if len(req.InputArguments) < 1 {
				return opcua.CallMethodResult{StatusCode: opcua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 1 {
				return opcua.CallMethodResult{StatusCode: opcua.BadTooManyArguments}
			}
			opResult := opcua.Good
			argsResults := make([]opcua.StatusCode, 1)
			subscriptionID, ok := req.InputArguments[0].(uint32)
			if !ok {
				opResult = opcua.BadInvalidArgument
				argsResults[0] = opcua.BadTypeMismatch
			}
			if opResult == opcua.BadInvalidArgument {
				return opcua.CallMethodResult{StatusCode: opResult, InputArgumentResults: argsResults}
			}
			sub, ok := srv.SubscriptionManager().Get(subscriptionID)
			if !ok {
				return opcua.CallMethodResult{StatusCode: opcua.BadSubscriptionIDInvalid}
			}
			session, ok := ctx.Value(SessionKey).(*Session)
			if !ok || sub.session != session {
				return opcua.CallMethodResult{StatusCode: opcua.BadUserAccessDenied}
			}
			svrHandles := []uint32{}
			cliHandles := []uint32{}
			for _, item := range sub.Items() {
				svrHandles = append(svrHandles, item.id)
				cliHandles = append(cliHandles, item.clientHandle)
			}
			return opcua.CallMethodResult{OutputArguments: []opcua.Variant{svrHandles, cliHandles}}
		})
	}

	if n, ok := nm.FindMethod(opcua.MethodIDServerResendData); ok {
		n.SetCallMethodHandler(func(ctx context.Context, req opcua.CallMethodRequest) opcua.CallMethodResult {
			if len(req.InputArguments) < 1 {
				return opcua.CallMethodResult{StatusCode: opcua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 1 {
				return opcua.CallMethodResult{StatusCode: opcua.BadTooManyArguments}
			}
			opResult := opcua.Good
			argsResults := make([]opcua.StatusCode, 1)
			subscriptionID, ok := req.InputArguments[0].(uint32)
			if !ok {
				opResult = opcua.BadInvalidArgument
				argsResults[0] = opcua.BadTypeMismatch
			}
			if opResult == opcua.BadInvalidArgument {
				return opcua.CallMethodResult{StatusCode: opResult, InputArgumentResults: argsResults}
			}
			sub, ok := srv.SubscriptionManager().Get(subscriptionID)
			if !ok {
				return opcua.CallMethodResult{StatusCode: opcua.BadSubscriptionIDInvalid}
			}
			session, ok := ctx.Value(SessionKey).(*Session)
			if !ok || sub.session != session {
				return opcua.CallMethodResult{StatusCode: opcua.BadUserAccessDenied}
			}
			sub.resendData()
			return opcua.CallMethodResult{OutputArguments: []opcua.Variant{}}
		})
	}
	return nil
}

func (srv *Server) buildEndpointDescriptions() []opcua.EndpointDescription {
	var eds []opcua.EndpointDescription
	if true {
		eds = append(eds, opcua.EndpointDescription{
			EndpointURL:         srv.endpointURL,
			Server:              srv.localDescription,
			ServerCertificate:   opcua.ByteString(srv.LocalCertificate()),
			SecurityMode:        opcua.MessageSecurityModeNone,
			SecurityPolicyURI:   opcua.SecurityPolicyURINone,
			TransportProfileURI: opcua.TransportProfileURIUaTcpTransport,
			SecurityLevel:       byte(0),
			UserIdentityTokens: []opcua.UserTokenPolicy{
				{
					PolicyID:          opcua.UserTokenTypeAnonymous.String(),
					TokenType:         opcua.UserTokenTypeAnonymous,
					SecurityPolicyURI: opcua.SecurityPolicyURINone,
				},
			},
		})
	}
	if true {
		eds = append(eds, opcua.EndpointDescription{
			EndpointURL:         srv.endpointURL,
			Server:              srv.localDescription,
			ServerCertificate:   opcua.ByteString(srv.LocalCertificate()),
			SecurityMode:        opcua.MessageSecurityModeSignAndEncrypt,
			SecurityPolicyURI:   opcua.SecurityPolicyURIBasic256Sha256,
			TransportProfileURI: opcua.TransportProfileURIUaTcpTransport,
			SecurityLevel:       byte(1),
			UserIdentityTokens: []opcua.UserTokenPolicy{
				{
					PolicyID:          opcua.UserTokenTypeAnonymous.String(),
					TokenType:         opcua.UserTokenTypeAnonymous,
					SecurityPolicyURI: opcua.SecurityPolicyURINone,
				},
				{
					PolicyID:          opcua.UserTokenTypeUserName.String(),
					TokenType:         opcua.UserTokenTypeUserName,
					SecurityPolicyURI: opcua.SecurityPolicyURIBasic256Sha256,
				},
			},
		})
	}

	return eds
}
