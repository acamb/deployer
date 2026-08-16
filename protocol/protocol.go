package protocol

type Command int

const (
	Deploy Command = iota
	Stop
	Start
	Restart
	Logs
	Revisions
	Push
	Ports
	LbStatus
)

func (c Command) String() string {
	switch c {
	case Deploy:
		return "Deploy"
	case Stop:
		return "Stop"
	case Start:
		return "Start"
	case Restart:
		return "Restart"
	case Logs:
		return "Logs"
	case Revisions:
		return "Revisions"
	case Push:
		return "Push"
	case Ports:
		return "Ports"
	case LbStatus:
		return "LbStatus"
	default:
		return "Unknown Command"
	}
}

type Status int

const (
	Ok Status = iota
	Ko
	NotReady
)

func (s Status) String() string {
	switch s {
	case Ok:
		return "Ok"
	case Ko:
		return "Ko"
	case NotReady:
		return "NotReady"
	default:
		return "Unknown Status"
	}
}

type Request struct {
	Version     string
	Command     Command
	Name        string
	TarSize     int64
	ComposeFile []byte
	Revision    string
	DeleteFiles bool
	Prune       bool
	Port        string // only used in Ports command
	// EKVS integration: these fields are optional and are populated only
	// when the client has EKVS enabled (see client/config).
	// They accompany requests that start a container (Deploy, Start, Restart)
	// so the server can invoke `ekvs cli ... exec` to inject secrets.
	EkvsEnable     bool
	EkvsServer     string
	EkvsProject    string
	EkvsPrivateKey []byte
	// Continuity integration: these fields are optional and are populated
	// only when the client has Continuity enabled (see client/config).
	// They accompany requests that start a container (Deploy, Start,
	// Restart) so the server can register/update the corresponding
	// backend on a Continuity load balancer pool.
	// ContinuityConfig carries the raw bytes of the client's Continuity
	// CLI configuration file (host/port/default_pool/auth_key). When
	// ContinuityPrivateKey is empty, auth_key is expected to already
	// point to a key present on the server (placed there manually).
	// ContinuityAdvertiseBase is the base URL (scheme included, no port)
	// under which the container must be reachable by Continuity. It is a
	// per-project property supplied by the client and has no server-side
	// default.
	ContinuityEnable          bool
	ContinuityConfig          []byte
	ContinuityPrivateKey      []byte
	ContinuityPool            string
	ContinuityHealthCheckPath string
	ContinuityInternalPort    string
	ContinuityRemovePrevious  bool
	ContinuityAdvertiseBase   string
}

func (r Request) String() string {
	return "Command: " + r.Command.String()
}

type Response struct {
	Status  Status
	Message string
}

type RevisionsDetails struct {
	Revisions []string `json:"revisions"`
}

type PortsResponse struct {
	Port []Port `json:"ports"`
}

type Port struct {
	LocalPort string `json:"localPort"`
	BindPort  string `json:"bindPort"`
	Protocol  string `json:"protocol"`
	Address   string `json:"address"`
}

// LbStatusResponse mirrors the configuration of the Continuity pool a project
// is published on, as returned by the LbStatus command (essentially the output
// of `continuity pool config`).
type LbStatusResponse struct {
	Hostname string      `json:"hostname"`
	Backends []LbBackend `json:"backends"`
}

type LbBackend struct {
	Address         string `json:"address"`
	Status          string `json:"status"`
	HealthCheckPath string `json:"healthCheckPath"`
	Conditional     bool   `json:"conditional"`
}

func (r Response) String() string {
	return "Status: " + r.Status.String() + ", Message: " + r.Message
}
