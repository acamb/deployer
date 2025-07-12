package protocol

type Command int

const (
	Deploy Command = iota
	Stop
	Start
	Restart
	Logs
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
	Command     Command
	Name        string
	TarImage    []byte
	ComposeFile []byte
}

func (r Request) String() string {
	return "Command: " + r.Command.String()
}

type Response struct {
	Status  Status
	Message string
}

func (r Response) String() string {
	return "Status: " + r.Status.String() + ", Message: " + r.Message
}
