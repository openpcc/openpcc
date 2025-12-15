package wallet

import (
	"errors"
	"fmt"
)

// ClosedError indicates a payment could not be began due to the wallet
// being closed. If this error contains [ErrCloseCalled] it means that the wallet
// was closed due to [Wallet.Close] being called, in other cases it signals that
// the wallet is closed due to an unrecoverable internal error being encountered.
type ClosedError struct {
	Err error
}

func (e ClosedError) Error() string {
	return fmt.Sprintf("unable to begin payment, wallet is closed: %s", e.Err.Error())
}

func (e ClosedError) Unwrap() error {
	return e.Err
}

func (e ClosedError) CloseCalled() bool {
	return errors.Is(e.Err, ErrCloseCalled)
}

func (e ClosedError) InternalError() bool {
	return !errors.Is(e.Err, ErrCloseCalled)
}

// ErrClosed indicates a payment could not be began because the wallet was closed.
var ErrCloseCalled = errors.New("wallet.Close was called")
