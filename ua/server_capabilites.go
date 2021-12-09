package ua

// ServerCapabilities contains the server capabilities.
type ServerCapabilities struct {
	LocaleIDArray                []string
	MaxStringLength              uint32
	MaxArrayLength               uint32
	MaxByteStringLength          uint32
	MaxBrowseContinuationPoints  uint16
	MaxHistoryContinuationPoints uint16
	MaxQueryContinuationPoints   uint16
	MinSupportedSampleRate       float64
	ServerProfileArray           []string
	OperationLimits              *OperationLimits
}

// NewServerCapabilities returns a ServerCapabilities structure with default values.
func NewServerCapabilities() *ServerCapabilities {
	return &ServerCapabilities{
		LocaleIDArray:                []string{"en"},
		MaxStringLength:              4096,
		MaxArrayLength:               4096,
		MaxByteStringLength:          4096,
		MaxBrowseContinuationPoints:  10,
		MaxHistoryContinuationPoints: 100,
		MaxQueryContinuationPoints:   0,
		MinSupportedSampleRate:       100,
		ServerProfileArray:           []string{"http://opcfoundation.org/UA-Profile/Server/StandardUA2017", "http://opcfoundation.org/UAProfile/Server/Methods"},
		OperationLimits:              NewOperationLimits(),
	}
}

// OperationLimits contains the server's operation limits.
type OperationLimits struct {
	MaxNodesPerRead                          uint32
	MaxNodesPerHistoryReadData               uint32
	MaxNodesPerHistoryReadEvents             uint32
	MaxNodesPerWrite                         uint32
	MaxNodesPerHistoryUpdateData             uint32
	MaxNodesPerHistoryUpdateEvents           uint32
	MaxNodesPerMethodCall                    uint32
	MaxNodesPerBrowse                        uint32
	MaxNodesPerRegisterNodes                 uint32
	MaxNodesPerTranslateBrowsePathsToNodeIds uint32
	MaxNodesPerNodeManagement                uint32
	MaxMonitoredItemsPerCall                 uint32
}

// NewOperationLimits returns a OperationLimits structure with default values.
func NewOperationLimits() *OperationLimits {
	return &OperationLimits{
		MaxNodesPerRead:                          1000,
		MaxNodesPerHistoryReadData:               1000,
		MaxNodesPerHistoryReadEvents:             1000,
		MaxNodesPerWrite:                         1000,
		MaxNodesPerHistoryUpdateData:             1000,
		MaxNodesPerHistoryUpdateEvents:           1000,
		MaxNodesPerMethodCall:                    1000,
		MaxNodesPerBrowse:                        1000,
		MaxNodesPerRegisterNodes:                 1000,
		MaxNodesPerTranslateBrowsePathsToNodeIds: 1000,
		MaxNodesPerNodeManagement:                1000,
		MaxMonitoredItemsPerCall:                 1000,
	}
}
