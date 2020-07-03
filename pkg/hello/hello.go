package hello

type HelloSayer interface {
	SayHello() string
}

type helloSayerImpl struct{}

func (helloSayerImpl) SayHello() string { return "goodbye" }

func NewHelloSayer() HelloSayer {
	return helloSayerImpl{}
}
