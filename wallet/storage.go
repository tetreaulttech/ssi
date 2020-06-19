package wallet

import "errors"

var ErrorNotFound = errors.New("not found")

type Storage interface {
	create(item item) error
	read(id string) (item item, err error)
	update(item item) error
	delete(id string) error
}

type item struct {
	ID       string `json:"_id"`
	Revision string `json:"_rev,omitempty"`
	Item     string `json:"item"`
	ItemKey  string `json:"itemKey,omitempty"`
}
