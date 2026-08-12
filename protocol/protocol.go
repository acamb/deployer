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
	// ContinuityAdvertiseBase is the optional base URL (scheme included,
	// no port) under which the container must be reachable by Continuity.
	// When empty the server falls back to its own configuration.
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

func (r Response) String() string {
	return "Status: " + r.Status.String() + ", Message: " + r.Message
}
