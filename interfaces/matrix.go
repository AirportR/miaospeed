package interfaces

type SlaveRequestMatrixType string

const (
	MatrixAverageSpeed   SlaveRequestMatrixType = "SPEED_AVERAGE"
	MatrixMaxSpeed       SlaveRequestMatrixType = "SPEED_MAX"
	MatrixPerSecondSpeed SlaveRequestMatrixType = "SPEED_PER_SECOND"

	MatrixUDPType SlaveRequestMatrixType = "UDP_TYPE"

	MatrixInboundGeoIP  SlaveRequestMatrixType = "GEOIP_INBOUND"
	MatrixOutboundGeoIP SlaveRequestMatrixType = "GEOIP_OUTBOUND"

	MatrixScriptTest    SlaveRequestMatrixType = "TEST_SCRIPT"
	MatrixHTTPPing      SlaveRequestMatrixType = "TEST_PING_CONN"
	MatrixRTTPing       SlaveRequestMatrixType = "TEST_PING_RTT"
	MatrixMAXHTTPPing   SlaveRequestMatrixType = "TEST_PING_MAX_CONN"
	MatrixMAXRTTPing    SlaveRequestMatrixType = "TEST_PING_MAX_RTT"
	MatrixTotalHTTPPing SlaveRequestMatrixType = "TEST_PING_TOTAL_CONN"
	MatrixTotalRTTPing  SlaveRequestMatrixType = "TEST_PING_TOTAL_RTT"
	MatrixSDRTT         SlaveRequestMatrixType = "TEST_PING_SD_RTT"
	MatrixSDHTTP        SlaveRequestMatrixType = "TEST_PING_SD_CONN"
	MatrixHTTPCode      SlaveRequestMatrixType = "TEST_HTTP_CODE"
	MatrixPacketLoss    SlaveRequestMatrixType = "TEST_PING_PACKET_LOSS"
	MatrixSleep         SlaveRequestMatrixType = "DEBUG_SLEEP"
	MatrixInvalid       SlaveRequestMatrixType = "INVALID"
)

func (srmt *SlaveRequestMatrixType) Valid() bool {
	if srmt == nil {
		return false
	}

	switch *srmt {
	case MatrixAverageSpeed, MatrixMaxSpeed, MatrixPerSecondSpeed,
		MatrixUDPType,
		MatrixInboundGeoIP, MatrixOutboundGeoIP,
		MatrixScriptTest, MatrixHTTPPing, MatrixRTTPing,
		MatrixMAXHTTPPing, MatrixMAXRTTPing,
		MatrixTotalHTTPPing, MatrixTotalRTTPing,
		MatrixSDRTT, MatrixSDHTTP, MatrixHTTPCode, MatrixPacketLoss:
		return true
	}

	return false
}

// Matrix is the the atom attribute for a job
// e.g. to fetch the RTTPing of a node,
// it calls RTTPing matrix, which would initiate
// a ping macro and return the RTTPing attribute
type SlaveRequestMatrix interface {
	// define the matrix type to match
	Type() SlaveRequestMatrixType

	// define which macro job to run
	MacroJob() SlaveRequestMacroType

	// define the function to extract attribute
	// from macro result
	Extract(SlaveRequestMatrixEntry, SlaveRequestMacro)
}

type MatrixResponse struct {
	Type    SlaveRequestMatrixType
	Payload string
}
