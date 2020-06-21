package transport

type Client interface {
	Send()
}

type Server interface {
	Receive()
}
