package tunnel

const (
	// CurrentProtocolVersion is the version of the protocol the agent
	// and controllers speak.  This should be increased only if there are
	// incompatible protobuf message flows.  If an agent connects to
	// a controller and the versions do not match, the controller will
	// close the connection.
	CurrentProtocolVersion = 10
)
