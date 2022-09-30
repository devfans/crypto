package crypto


type ECDSASigner interface {
	Sign([]byte) 
}