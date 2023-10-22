package server

import (
	"crypto/rsa"
	"crypto/tls"
	_ "embed"
	"fmt"
	"log"
	"math"
	mathrand "math/rand"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awcullen/opcua/ua"
	"github.com/gammazero/workerpool"
)

const (
	// the minimum number of milliseconds that a session may be unused before being closed by the server. (2 min)
	minSessionTimeout float64 = 10 * 1000
	// the maximum number of milliseconds that a session may be unused before being closed by the server. (60 min)
	maxSessionTimeout float64 = 3600 * 1000
	// the default number of sessions that may be active. (no limit)
	defaultMaxSessionCount uint32 = 0
	// the default number of subscriptions that may be active. (no limit)
	defaultMaxSubscriptionCount uint32 = 0
	// the default number of worker threads that may be created.
	defaultMaxWorkerThreads int = 4
	// the length of nonce in bytes.
	nonceLength int = 32
)

var (
	//go:embed nodeset_1_04.xml
	nodeset104 []byte
)

// Server implements an OpcUa server for clients.
type Server struct {
	sync.RWMutex
	localDescription                     ua.ApplicationDescription
	endpoints                            []ua.EndpointDescription
	maxSessionCount                      uint32
	maxSubscriptionCount                 uint32
	serverCapabilities                   *ua.ServerCapabilities
	buildInfo                            ua.BuildInfo
	certPath                             string
	keyPath                              string
	trustedCertsPath                     string
	trustedCRLsPath                      string
	issuerCertsPath                      string
	issuerCRLsPath                       string
	rejectedCertsPath                    string
	endpointURL                          string
	suppressCertificateExpired           bool
	suppressCertificateChainIncomplete   bool
	suppressCertificateRevocationUnknown bool
	maxBufferSize                        uint32
	maxMessageSize                       uint32
	maxChunkCount                        uint32
	maxWorkerThreads                     int
	serverDiagnostics                    bool
	trace                                bool
	localCertificate                     []byte
	localPrivateKey                      *rsa.PrivateKey
	closing                              chan struct{}
	state                                ua.ServerState
	secondsTillShutdown                  uint32
	shutdownReason                       ua.LocalizedText
	workerpool                           *workerpool.WorkerPool
	sessionManager                       *SessionManager
	subscriptionManager                  *SubscriptionManager
	namespaceManager                     *NamespaceManager
	serverUris                           []string
	startTime                            time.Time
	serverDiagnosticsSummary             *ua.ServerDiagnosticsSummaryDataType
	scheduler                            *Scheduler
	historian                            HistoryReadWriter
	allowSecurityPolicyNone              bool
	anonymousIdentityAuthenticator       AnonymousIdentityAuthenticator
	userNameIdentityAuthenticator        UserNameIdentityAuthenticator
	x509IdentityAuthenticator            X509IdentityAuthenticator
	issuedIdentityAuthenticator          IssuedIdentityAuthenticator
	rolesProvider                        RolesProvider
	rolePermissions                      []ua.RolePermissionType
	lastChannelID                        uint32
}

// New initializes a new instance of the Server.
// Specify the ApplicationDescription as defined in https://reference.opcfoundation.org/v104/Core/docs/Part4/7.1/
// The files must contain PEM encoded data.
// The endpointURL is in the form opc.tcp://[host]:[port]
func New(localDescription ua.ApplicationDescription, certPath, keyPath, endpointURL string, options ...Option) (*Server, error) {
	srv := &Server{
		localDescription:                   localDescription,
		certPath:                           certPath,
		keyPath:                            keyPath,
		endpointURL:                        endpointURL,
		maxSessionCount:                    defaultMaxSessionCount,
		maxSubscriptionCount:               defaultMaxSubscriptionCount,
		serverCapabilities:                 ua.NewServerCapabilities(),
		buildInfo:                          ua.BuildInfo{},
		suppressCertificateExpired:         false,
		suppressCertificateChainIncomplete: false,
		maxBufferSize:                      defaultMaxBufferSize,
		maxMessageSize:                     defaultMaxMessageSize,
		maxChunkCount:                      defaultMaxChunkCount,
		maxWorkerThreads:                   defaultMaxWorkerThreads,
		serverDiagnostics:                  true,
		trace:                              false,
		closing:                            make(chan struct{}),
		serverUris:                         []string{localDescription.ApplicationURI},
		state:                              ua.ServerStateUnknown,
		startTime:                          time.Now(),
		serverDiagnosticsSummary:           &ua.ServerDiagnosticsSummaryDataType{},
		rolesProvider:                      DefaultRolesProvider,
		rolePermissions:                    DefaultRolePermissions,
		lastChannelID:                      mathrand.Uint32(),
	}

	// apply each option to the default
	for _, opt := range options {
		if err := opt(srv); err != nil {
			return nil, err
		}
	}

	srv.workerpool = workerpool.New(srv.maxWorkerThreads)
	srv.sessionManager = NewSessionManager(srv)
	srv.subscriptionManager = NewSubscriptionManager(srv)
	srv.namespaceManager = NewNamespaceManager(srv)
	srv.scheduler = NewScheduler(srv)

	cert, err := tls.LoadX509KeyPair(srv.certPath, srv.keyPath)
	if err != nil {
		log.Printf("Error loading x509 key pair. %s\n", err)
		return nil, err
	}
	srv.localCertificate = cert.Certificate[0]
	srv.localPrivateKey, _ = cert.PrivateKey.(*rsa.PrivateKey)

	if err := srv.initializeNamespace(); err != nil {
		log.Printf("Error initializing namespace. %s\n", err)
		return nil, err
	}
	return srv, nil
}

// LocalDescription gets the application description.
func (srv *Server) LocalDescription() ua.ApplicationDescription {
	srv.RLock()
	defer srv.RUnlock()
	return srv.localDescription
}

// LocalCertificate gets the certificate for the local application.
func (srv *Server) LocalCertificate() []byte {
	srv.RLock()
	defer srv.RUnlock()
	return srv.localCertificate
}

// EndpointURL gets the endpoint url.
func (srv *Server) EndpointURL() string {
	srv.RLock()
	defer srv.RUnlock()
	return srv.endpointURL
}

// Endpoints gets the endpoint descriptions.
func (srv *Server) Endpoints() []ua.EndpointDescription {
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
func (srv *Server) State() ua.ServerState {
	srv.RLock()
	defer srv.RUnlock()
	return srv.state
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
func (srv *Server) RolePermissions() []ua.RolePermissionType {
	srv.RLock()
	defer srv.RUnlock()
	return srv.rolePermissions
}

// WorkerPool gets a pool of workers.
func (srv *Server) WorkerPool() *workerpool.WorkerPool {
	srv.RLock()
	defer srv.RUnlock()
	return srv.workerpool
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
func (srv *Server) ServerCapabilities() *ua.ServerCapabilities {
	srv.RLock()
	defer srv.RUnlock()
	return srv.serverCapabilities
}

// ListenAndServe listens on the EndpointURL for incoming connections and then
// handles service requests.
// ListenAndServe always returns a non-nil error. After server Close,
// the returned error is BadServerHalted.
func (srv *Server) ListenAndServe() error {
	srv.Lock()
	if srv.state != ua.ServerStateUnknown {
		srv.Unlock()
		return ua.BadInternalError
	}
	srv.state = ua.ServerStateRunning
	srv.Unlock()

	baseURL, err := url.Parse(srv.endpointURL)
	if err != nil {
		// log.Printf("Error opening secure channel listener. %s\n", err.Error())
		return ua.BadTCPEndpointURLInvalid
	}

	ln, err := net.Listen("tcp", ":"+baseURL.Port())
	if err != nil {
		// log.Printf("Error opening secure channel listener. %s\n", err.Error())
		return ua.BadResourceUnavailable
	}

	go func() {
		<-srv.closing
		ln.Close()
	}()

	var wg sync.WaitGroup
	err = srv.serve(ln, &wg)

	// wait until channels closed
	wg.Wait()

	// stop workers.
	srv.workerpool.StopWait()

	return err
}

// Close server.
func (srv *Server) Close() error {
	srv.Lock()
	if srv.state != ua.ServerStateRunning {
		srv.Unlock()
		return ua.BadInternalError
	}
	srv.state = ua.ServerStateShutdown
	srv.Unlock()

	// allow for existing clients to exit gracefully
	srv.shutdownReason = ua.NewLocalizedText("Closing", "")
	for i := 3; i > 0; i-- {
		srv.secondsTillShutdown = uint32(i)
		time.Sleep(time.Second)
	}
	srv.secondsTillShutdown = uint32(0)

	// begin closing channels
	close(srv.closing)
	return nil
}

// GetRoles returns the roles for the given user identity and connection information.
func (srv *Server) GetRoles(userIdentity any, applicationURI string, endpointURL string) ([]ua.NodeID, error) {
	return srv.rolesProvider.GetRoles(userIdentity, applicationURI, endpointURL)
}

func (srv *Server) serve(ln net.Listener, wg *sync.WaitGroup) error {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if srv.State() != ua.ServerStateRunning {
				return ua.BadServerHalted
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
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
			return ua.BadTCPInternalError

		}
		delay = 0
		wg.Add(1)
		go srv.handleConnection(conn, wg)
	}
}

// handleConnection wraps conn in ServerSecureChannel and handles service requests.
func (srv *Server) handleConnection(conn net.Conn, wg *sync.WaitGroup) {
	defer conn.Close()
	defer wg.Done()
	ch := newServerSecureChannel(srv, conn, srv.trace)
	err := ch.Open()
	if err != nil {
		// log.Printf("Error opening secure channel. %s\n", err)
		if c, ok := err.(ua.StatusCode); ok {
			ch.Abort(c, "")
		}
		return
	}
	// log.Printf("Success opening secure channel '%d'.\n", ch.channelID)
	closing := make(chan struct{})
	defer close(closing)
	// setup the cancellation to abort reads in process
	go func() {
		select {
		case <-srv.closing:
			ch.Close()
		case <-closing:
		}
	}()
	err = srv.requestWorker(ch)
	if err != nil {
		// log.Printf("Error handling service request for channel id '%d'. %s\n", ch.channelID, err)
		return
	}
	// log.Printf("Success closing secure channel '%d'.\n", ch.channelID)
}

// requestWorker receives service requests from channel and processes them.
func (srv *Server) requestWorker(ch *serverSecureChannel) error {
	for {
		req, id, err := ch.readRequest()
		if err != nil {
			return err
		}
		err = srv.handleRequest(ch, req, id)
		if err != nil {
			return err
		}
	}
}

// handleRequest directs the request to the correct handler depending on the type of request.
func (srv *Server) handleRequest(ch *serverSecureChannel, req ua.ServiceRequest, requestid uint32) error {
	switch req := req.(type) {
	case *ua.PublishRequest:
		return srv.handlePublish(ch, requestid, req)
	case *ua.RepublishRequest:
		return srv.handleRepublish(ch, requestid, req)
	case *ua.ReadRequest:
		return srv.handleRead(ch, requestid, req)
	case *ua.WriteRequest:
		return srv.handleWrite(ch, requestid, req)
	case *ua.CallRequest:
		return srv.handleCall(ch, requestid, req)
	case *ua.BrowseRequest:
		return srv.handleBrowse(ch, requestid, req)
	case *ua.BrowseNextRequest:
		return srv.handleBrowseNext(ch, requestid, req)
	case *ua.TranslateBrowsePathsToNodeIDsRequest:
		return srv.handleTranslateBrowsePathsToNodeIds(ch, requestid, req)
	case *ua.CreateSubscriptionRequest:
		return srv.handleCreateSubscription(ch, requestid, req)
	case *ua.ModifySubscriptionRequest:
		return srv.handleModifySubscription(ch, requestid, req)
	case *ua.SetPublishingModeRequest:
		return srv.handleSetPublishingMode(ch, requestid, req)
	case *ua.DeleteSubscriptionsRequest:
		return srv.handleDeleteSubscriptions(ch, requestid, req)
	case *ua.CreateMonitoredItemsRequest:
		return srv.handleCreateMonitoredItems(ch, requestid, req)
	case *ua.ModifyMonitoredItemsRequest:
		return srv.handleModifyMonitoredItems(ch, requestid, req)
	case *ua.SetMonitoringModeRequest:
		return srv.handleSetMonitoringMode(ch, requestid, req)
	case *ua.DeleteMonitoredItemsRequest:
		return srv.handleDeleteMonitoredItems(ch, requestid, req)
	case *ua.HistoryReadRequest:
		return srv.handleHistoryRead(ch, requestid, req)
	case *ua.CreateSessionRequest:
		return srv.handleCreateSession(ch, requestid, req)
	case *ua.ActivateSessionRequest:
		return srv.handleActivateSession(ch, requestid, req)
	case *ua.CloseSessionRequest:
		return srv.handleCloseSession(ch, requestid, req)
	case *ua.OpenSecureChannelRequest:
		return ch.handleOpenSecureChannel(requestid, req)
	case *ua.CloseSecureChannelRequest:
		return ch.handleCloseSecureChannel(requestid, req)
	case *ua.FindServersRequest:
		return srv.findServers(ch, requestid, req)
	case *ua.GetEndpointsRequest:
		return srv.getEndpoints(ch, requestid, req)
	case *ua.RegisterNodesRequest:
		return srv.handleRegisterNodes(ch, requestid, req)
	case *ua.UnregisterNodesRequest:
		return srv.handleUnregisterNodes(ch, requestid, req)
	case *ua.SetTriggeringRequest:
		return srv.handleSetTriggering(ch, requestid, req)
	case *ua.CancelRequest:
		return srv.handleCancel(ch, requestid, req)
	default:
		err := ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.Header().RequestHandle,
					ServiceResult: ua.BadServiceUnsupported,
				},
			},
			requestid,
		)
		if err != nil {
			return err
		}
		return nil
	}
}

func (srv *Server) initializeNamespace() error {
	nm := srv.NamespaceManager()
	if err := nm.LoadNodeSetFromBuffer(nodeset104); err != nil {
		return err
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerAuditing); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindNode(ua.MethodIDServerRequestServerStateChange); ok {
		nm.DeleteNode(n, true)
	}
	if n, ok := nm.FindNode(ua.MethodIDServerSetSubscriptionDurable); ok {
		nm.DeleteNode(n, true)
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServiceLevel); ok {
		n.SetValue(ua.NewDataValue(byte(255), 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerRedundancyRedundancySupport); ok {
		n.SetValue(ua.NewDataValue(int32(0), 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindNode(ua.VariableIDServerServerRedundancyCurrentServerID); ok {
		nm.DeleteNode(n, false)
	}
	if n, ok := nm.FindNode(ua.VariableIDServerServerRedundancyRedundantServerArray); ok {
		nm.DeleteNode(n, true)
	}
	if n, ok := nm.FindNode(ua.VariableIDServerServerRedundancyServerNetworkGroups); ok {
		nm.DeleteNode(n, true)
	}
	if n, ok := nm.FindNode(ua.VariableIDServerServerRedundancyServerURIArray); ok {
		nm.DeleteNode(n, true)
	}

	if n, ok := nm.FindVariable(ua.VariableIDServerNamespaceArray); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.NamespaceUris(), 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerArray); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.ServerUris(), 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatus); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(
				ua.ServerStatusDataType{
					StartTime:           srv.startTime,
					CurrentTime:         time.Now(),
					State:               srv.state,
					BuildInfo:           srv.buildInfo,
					ShutdownReason:      srv.shutdownReason,
					SecondsTillShutdown: srv.secondsTillShutdown,
				}, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusState); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(int32(srv.State()), 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusCurrentTime); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(time.Now(), 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusSecondsTillShutdown); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.secondsTillShutdown, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusShutdownReason); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.shutdownReason, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusStartTime); ok {
		n.SetValue(ua.NewDataValue(srv.startTime, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusBuildInfo); ok {
		n.SetValue(ua.NewDataValue(srv.buildInfo, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusBuildInfoProductURI); ok {
		n.SetValue(ua.NewDataValue(srv.buildInfo.ProductURI, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusBuildInfoManufacturerName); ok {
		n.SetValue(ua.NewDataValue(srv.buildInfo.ManufacturerName, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusBuildInfoProductName); ok {
		n.SetValue(ua.NewDataValue(srv.buildInfo.ProductName, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusBuildInfoSoftwareVersion); ok {
		n.SetValue(ua.NewDataValue(srv.buildInfo.SoftwareVersion, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusBuildInfoBuildNumber); ok {
		n.SetValue(ua.NewDataValue(srv.buildInfo.BuildNumber, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerStatusBuildInfoBuildDate); ok {
		n.SetValue(ua.NewDataValue(srv.buildInfo.BuildDate, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesLocaleIDArray); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.LocaleIDArray, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesMaxStringLength); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.MaxStringLength, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesMaxArrayLength); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.MaxArrayLength, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesMaxByteStringLength); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.MaxByteStringLength, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesMaxBrowseContinuationPoints); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.MaxBrowseContinuationPoints, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesMaxHistoryContinuationPoints); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.MaxHistoryContinuationPoints, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesMaxQueryContinuationPoints); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.MaxQueryContinuationPoints, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesMinSupportedSampleRate); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.MinSupportedSampleRate, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesServerProfileArray); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.ServerProfileArray, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesAccessHistoryDataCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesInsertDataCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesReplaceDataCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesUpdateDataCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesDeleteRawCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesDeleteAtTimeCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesAccessHistoryEventsCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesMaxReturnDataValues); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesMaxReturnEventValues); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesInsertAnnotationCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesInsertEventCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesReplaceEventCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDHistoryServerCapabilitiesUpdateEventCapability); ok {
		n.SetValue(ua.NewDataValue(false, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxMonitoredItemsPerCall); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxMonitoredItemsPerCall, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerBrowse); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerBrowse, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryReadData); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerHistoryReadData, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryReadEvents); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerHistoryReadEvents, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryUpdateData); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerHistoryUpdateData, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerHistoryUpdateEvents); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerHistoryUpdateEvents, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerMethodCall); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerMethodCall, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerNodeManagement); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerNodeManagement, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerRead); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerRead, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerRegisterNodes); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerRegisterNodes, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerTranslateBrowsePathsToNodeIDs); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerTranslateBrowsePathsToNodeIds, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerCapabilitiesOperationLimitsMaxNodesPerWrite); ok {
		n.SetValue(ua.NewDataValue(srv.serverCapabilities.OperationLimits.MaxNodesPerWrite, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindObject(ua.ObjectIDServerServerCapabilitiesModellingRules); ok {
		if mandatory, ok := nm.FindObject(ua.ObjectIDModellingRuleMandatory); ok {
			mandatory.SetReferences(append(mandatory.References(), ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(n.NodeID()))))
			n.SetReferences(append(n.References(), ua.NewReference(ua.ReferenceTypeIDHasComponent, false, ua.NewExpandedNodeID(mandatory.NodeID()))))
		}
		if mandatoryPlaceholder, ok := nm.FindObject(ua.ObjectIDModellingRuleMandatoryPlaceholder); ok {
			mandatoryPlaceholder.SetReferences(append(mandatoryPlaceholder.References(), ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(n.NodeID()))))
			n.SetReferences(append(n.References(), ua.NewReference(ua.ReferenceTypeIDHasComponent, false, ua.NewExpandedNodeID(mandatoryPlaceholder.NodeID()))))
		}
		if optional, ok := nm.FindObject(ua.ObjectIDModellingRuleOptional); ok {
			optional.SetReferences(append(optional.References(), ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(n.NodeID()))))
			n.SetReferences(append(n.References(), ua.NewReference(ua.ReferenceTypeIDHasComponent, false, ua.NewExpandedNodeID(optional.NodeID()))))
		}
		if optionalPlaceholder, ok := nm.FindObject(ua.ObjectIDModellingRuleOptionalPlaceholder); ok {
			optionalPlaceholder.SetReferences(append(optionalPlaceholder.References(), ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(n.NodeID()))))
			n.SetReferences(append(n.References(), ua.NewReference(ua.ReferenceTypeIDHasComponent, false, ua.NewExpandedNodeID(optionalPlaceholder.NodeID()))))
		}
	}
	if nr, ok := nm.FindVariable(ua.VariableIDModellingRuleMandatoryNamingRule); ok {
		nr.SetValue(ua.NewDataValue(int32(1), 0, time.Now(), 0, time.Now(), 0))
	}
	if nr, ok := nm.FindVariable(ua.VariableIDModellingRuleMandatoryPlaceholderNamingRule); ok {
		nr.SetValue(ua.NewDataValue(int32(1), 0, time.Now(), 0, time.Now(), 0))
	}
	if nr, ok := nm.FindVariable(ua.VariableIDModellingRuleOptionalNamingRule); ok {
		nr.SetValue(ua.NewDataValue(int32(2), 0, time.Now(), 0, time.Now(), 0))
	}
	if nr, ok := nm.FindVariable(ua.VariableIDModellingRuleOptionalPlaceholderNamingRule); ok {
		nr.SetValue(ua.NewDataValue(int32(2), 0, time.Now(), 0, time.Now(), 0))
	}

	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsEnabledFlag); ok {
		n.accessLevel = ua.AccessLevelsCurrentRead
		n.SetValue(ua.NewDataValue(srv.serverDiagnostics, 0, time.Now(), 0, time.Now(), 0))
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummary); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryCumulatedSessionCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.CumulatedSessionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryCumulatedSubscriptionCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.CumulatedSubscriptionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryCurrentSessionCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.CurrentSessionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryCurrentSubscriptionCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.CurrentSubscriptionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryServerViewCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.ServerViewCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummarySecurityRejectedSessionCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.SecurityRejectedSessionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummarySessionAbortCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.SessionAbortCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryPublishingIntervalCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.PublishingIntervalCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummarySecurityRejectedRequestsCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.SecurityRejectedRequestsCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryRejectedRequestsCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.RejectedRequestsCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummaryRejectedSessionCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.RejectedSessionCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsServerDiagnosticsSummarySessionTimeoutCount); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			return ua.NewDataValue(srv.serverDiagnosticsSummary.SessionTimeoutCount, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindVariable(ua.VariableIDServerServerDiagnosticsSubscriptionDiagnosticsArray); ok {
		n.SetReadValueHandler(func(session *Session, req ua.ReadValueID) ua.DataValue {
			if !srv.serverDiagnostics {
				return ua.NewDataValue(nil, 0, time.Now(), 0, time.Now(), 0)
			}
			a := make([]ua.ExtensionObject, 0, 16)
			for _, s := range srv.SubscriptionManager().subscriptionsByID {
				s.RLock()
				e := ua.SubscriptionDiagnosticsDataType{
					SessionID:                  s.sessionId,
					SubscriptionID:             s.id,
					Priority:                   s.priority,
					PublishingInterval:         s.publishingInterval,
					MaxKeepAliveCount:          s.maxKeepAliveCount,
					MaxLifetimeCount:           s.maxLifetimeCount,
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
					CurrentKeepAliveCount:        s.keepAliveCount,
					CurrentLifetimeCount:         s.lifetimeCount,
					UnacknowledgedMessageCount:   s.unacknowledgedMessageCount,
					// DiscardedMessageCount:        uint32(0),
					MonitoredItemCount:           s.monitoredItemCount,
					DisabledMonitoredItemCount:   s.disabledMonitoredItemCount,
					MonitoringQueueOverflowCount: s.monitoringQueueOverflowCount,
					NextSequenceNumber:           s.nextSequenceNumber,
					// EventQueueOverFlowCount:      uint32(0),
				}
				s.RUnlock()
				a = append(a, e)
			}
			return ua.NewDataValue(a, 0, time.Now(), 0, time.Now(), 0)
		})
	}
	if n, ok := nm.FindNode(ua.VariableIDServerServerDiagnosticsSamplingIntervalDiagnosticsArray); ok {
		nm.DeleteNode(n, true)
	}

	if n, ok := nm.FindMethod(ua.MethodIDServerGetMonitoredItems); ok {
		n.SetCallMethodHandler(func(session *Session, req ua.CallMethodRequest) ua.CallMethodResult {
			if len(req.InputArguments) < 1 {
				return ua.CallMethodResult{StatusCode: ua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 1 {
				return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
			}
			opResult := ua.Good
			argsResults := make([]ua.StatusCode, 1)
			subscriptionID, ok := req.InputArguments[0].(uint32)
			if !ok {
				opResult = ua.BadInvalidArgument
				argsResults[0] = ua.BadTypeMismatch
			}
			if opResult == ua.BadInvalidArgument {
				return ua.CallMethodResult{StatusCode: opResult, InputArgumentResults: argsResults}
			}
			sub, ok := srv.SubscriptionManager().Get(subscriptionID)
			if !ok {
				return ua.CallMethodResult{StatusCode: ua.BadSubscriptionIDInvalid}
			}
			if session == nil || sub.session != session {
				return ua.CallMethodResult{StatusCode: ua.BadUserAccessDenied}
			}
			svrHandles := []uint32{}
			cliHandles := []uint32{}
			for _, item := range sub.Items() {
				svrHandles = append(svrHandles, item.ID())
				cliHandles = append(cliHandles, item.ClientHandle())
			}
			return ua.CallMethodResult{OutputArguments: []ua.Variant{svrHandles, cliHandles}}
		})
	}

	if n, ok := nm.FindMethod(ua.MethodIDServerGetMonitoredItems); ok {
		n.SetCallMethodHandler(func(session *Session, req ua.CallMethodRequest) ua.CallMethodResult {
			if len(req.InputArguments) < 1 {
				return ua.CallMethodResult{StatusCode: ua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 1 {
				return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
			}
			opResult := ua.Good
			argsResults := make([]ua.StatusCode, 1)
			subscriptionID, ok := req.InputArguments[0].(uint32)
			if !ok {
				opResult = ua.BadInvalidArgument
				argsResults[0] = ua.BadTypeMismatch
			}
			if opResult == ua.BadInvalidArgument {
				return ua.CallMethodResult{StatusCode: opResult, InputArgumentResults: argsResults}
			}
			sub, ok := srv.SubscriptionManager().Get(subscriptionID)
			if !ok {
				return ua.CallMethodResult{StatusCode: ua.BadSubscriptionIDInvalid}
			}
			if session == nil || sub.session != session {
				return ua.CallMethodResult{StatusCode: ua.BadUserAccessDenied}
			}
			svrHandles := []uint32{}
			cliHandles := []uint32{}
			for _, item := range sub.Items() {
				svrHandles = append(svrHandles, item.ID())
				cliHandles = append(cliHandles, item.ClientHandle())
			}
			return ua.CallMethodResult{OutputArguments: []ua.Variant{svrHandles, cliHandles}}
		})
	}

	if n, ok := nm.FindMethod(ua.MethodIDServerResendData); ok {
		n.SetCallMethodHandler(func(session *Session, req ua.CallMethodRequest) ua.CallMethodResult {
			if len(req.InputArguments) < 1 {
				return ua.CallMethodResult{StatusCode: ua.BadArgumentsMissing}
			}
			if len(req.InputArguments) > 1 {
				return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
			}
			opResult := ua.Good
			argsResults := make([]ua.StatusCode, 1)
			subscriptionID, ok := req.InputArguments[0].(uint32)
			if !ok {
				opResult = ua.BadInvalidArgument
				argsResults[0] = ua.BadTypeMismatch
			}
			if opResult == ua.BadInvalidArgument {
				return ua.CallMethodResult{StatusCode: opResult, InputArgumentResults: argsResults}
			}
			sub, ok := srv.SubscriptionManager().Get(subscriptionID)
			if !ok {
				return ua.CallMethodResult{StatusCode: ua.BadSubscriptionIDInvalid}
			}
			if session == nil || sub.session != session {
				return ua.CallMethodResult{StatusCode: ua.BadUserAccessDenied}
			}
			sub.resendData()
			return ua.CallMethodResult{OutputArguments: []ua.Variant{}}
		})
	}
	return nil
}

func (srv *Server) buildEndpointDescriptions() []ua.EndpointDescription {
	eds := []ua.EndpointDescription{}
	if srv.allowSecurityPolicyNone {
		toks := []ua.UserTokenPolicy{}
		if srv.anonymousIdentityAuthenticator != nil {
			toks = append(toks, ua.UserTokenPolicy{
				PolicyID:          fmt.Sprintf("%s_%d", ua.UserTokenTypeAnonymous, len(eds)),
				TokenType:         ua.UserTokenTypeAnonymous,
				SecurityPolicyURI: ua.SecurityPolicyURINone,
			})
		}
		if srv.userNameIdentityAuthenticator != nil {
			toks = append(toks, ua.UserTokenPolicy{
				PolicyID:          fmt.Sprintf("%s_%d", ua.UserTokenTypeUserName, len(eds)),
				TokenType:         ua.UserTokenTypeUserName,
				SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			})
		}
		if srv.x509IdentityAuthenticator != nil {
			toks = append(toks, ua.UserTokenPolicy{
				PolicyID:          fmt.Sprintf("%s_%d", ua.UserTokenTypeCertificate, len(eds)),
				TokenType:         ua.UserTokenTypeCertificate,
				SecurityPolicyURI: ua.SecurityPolicyURIBasic256Sha256,
			})
		}
		eds = append(eds, ua.EndpointDescription{
			EndpointURL:         srv.endpointURL,
			Server:              srv.localDescription,
			ServerCertificate:   ua.ByteString(srv.LocalCertificate()),
			SecurityMode:        ua.MessageSecurityModeNone,
			SecurityPolicyURI:   ua.SecurityPolicyURINone,
			TransportProfileURI: ua.TransportProfileURIUaTcpTransport,
			SecurityLevel:       byte(len(eds)),
			UserIdentityTokens:  toks,
		})
	}

	uris := []string{
		ua.SecurityPolicyURIBasic128Rsa15,
		ua.SecurityPolicyURIBasic256,
		ua.SecurityPolicyURIBasic256Sha256,
		ua.SecurityPolicyURIAes128Sha256RsaOaep,
		ua.SecurityPolicyURIAes256Sha256RsaPss,
	}
	for _, uri := range uris {
		toks := []ua.UserTokenPolicy{}
		if srv.anonymousIdentityAuthenticator != nil {
			toks = append(toks, ua.UserTokenPolicy{
				PolicyID:          fmt.Sprintf("%s_%d", ua.UserTokenTypeAnonymous, len(eds)),
				TokenType:         ua.UserTokenTypeAnonymous,
				SecurityPolicyURI: ua.SecurityPolicyURINone,
			})
		}
		if srv.userNameIdentityAuthenticator != nil {
			toks = append(toks, ua.UserTokenPolicy{
				PolicyID:          fmt.Sprintf("%s_%d", ua.UserTokenTypeUserName, len(eds)),
				TokenType:         ua.UserTokenTypeUserName,
				SecurityPolicyURI: uri,
			})
		}
		if srv.x509IdentityAuthenticator != nil {
			toks = append(toks, ua.UserTokenPolicy{
				PolicyID:          fmt.Sprintf("%s_%d", ua.UserTokenTypeCertificate, len(eds)),
				TokenType:         ua.UserTokenTypeCertificate,
				SecurityPolicyURI: uri,
			})
		}
		eds = append(eds, ua.EndpointDescription{
			EndpointURL:         srv.endpointURL,
			Server:              srv.localDescription,
			ServerCertificate:   ua.ByteString(srv.LocalCertificate()),
			SecurityMode:        ua.MessageSecurityModeSign,
			SecurityPolicyURI:   uri,
			TransportProfileURI: ua.TransportProfileURIUaTcpTransport,
			SecurityLevel:       byte(len(eds)),
			UserIdentityTokens:  toks,
		})
	}
	for _, uri := range uris {
		toks := []ua.UserTokenPolicy{}
		if srv.anonymousIdentityAuthenticator != nil {
			toks = append(toks, ua.UserTokenPolicy{
				PolicyID:          fmt.Sprintf("%s_%d", ua.UserTokenTypeAnonymous, len(eds)),
				TokenType:         ua.UserTokenTypeAnonymous,
				SecurityPolicyURI: ua.SecurityPolicyURINone,
			})
		}
		if srv.userNameIdentityAuthenticator != nil {
			toks = append(toks, ua.UserTokenPolicy{
				PolicyID:          fmt.Sprintf("%s_%d", ua.UserTokenTypeUserName, len(eds)),
				TokenType:         ua.UserTokenTypeUserName,
				SecurityPolicyURI: uri,
			})
		}
		if srv.x509IdentityAuthenticator != nil {
			toks = append(toks, ua.UserTokenPolicy{
				PolicyID:          fmt.Sprintf("%s_%d", ua.UserTokenTypeCertificate, len(eds)),
				TokenType:         ua.UserTokenTypeCertificate,
				SecurityPolicyURI: uri,
			})
		}
		eds = append(eds, ua.EndpointDescription{
			EndpointURL:         srv.endpointURL,
			Server:              srv.localDescription,
			ServerCertificate:   ua.ByteString(srv.LocalCertificate()),
			SecurityMode:        ua.MessageSecurityModeSignAndEncrypt,
			SecurityPolicyURI:   uri,
			TransportProfileURI: ua.TransportProfileURIUaTcpTransport,
			SecurityLevel:       byte(len(eds)),
			UserIdentityTokens:  toks,
		})
	}
	return eds
}

// getNextChannelID gets next id in sequence, skipping zero.
func (srv *Server) getNextChannelID() uint32 {
	for {
		old := atomic.LoadUint32(&srv.lastChannelID)
		new := old
		if new == math.MaxUint32 {
			new = 0
		}
		new++
		if atomic.CompareAndSwapUint32(&srv.lastChannelID, old, new) {
			return new
		}
	}
}
