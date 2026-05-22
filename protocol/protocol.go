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
)

func (s Status) String() string {
	switch s {
	case Ok:
		return "Ok"
	case Ko:
		return "Ko"
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
