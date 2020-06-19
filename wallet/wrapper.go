package wallet

// Implementations of the Wrapper interface should wrap secrets by
// encrypting them with keys stored in a secure enclave or HSM.
type Wrapper interface {
	Wrap(secret []byte) (wrappedSecret []byte)
	Unwrap(wrappedSecret []byte) (secret []byte)
}
