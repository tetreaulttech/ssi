package wallet

import (
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"net/http"
	"strings"
)

type couchDBStorage struct {
	url string
}

func NewCouchDbStorage(dbname string) (Storage, error) {
	databases := make([]string, 0)

	// Make sure the database exists
	resp, err := resty.New().R().
		SetResult(databases).
		Get("http://localhost:5984/_all_dbs")
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, errors.New(http.StatusText(resp.StatusCode()))
	}

	url := fmt.Sprintf("http://localhost:5984/%s", dbname)

	for _, db := range databases {
		if strings.Compare(db, dbname) == 0 {
			return &couchDBStorage{url: url}, nil
		}
	}

	// Database doesn't exist yet - lets create it!
	resp, err = resty.New().R().
		Put(url)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, errors.New(http.StatusText(resp.StatusCode()))
	}

	return &couchDBStorage{url: url}, nil
}

func (c *couchDBStorage) create(item item) error {
	resp, err := resty.New().R().
		SetBody(item).
		Post(c.url)
	if err != nil {
		return err
	}
	if resp.IsError() {
		return errors.New(http.StatusText(resp.StatusCode()))
	}
	return nil
}

func (c *couchDBStorage) read(id string) (item, error) {
	var i item
	resp, err := resty.New().R().
		SetResult(&i).
		Get(fmt.Sprintf("%s/%s", c.url, id))
	if err != nil {
		return item{}, err
	}
	if resp.StatusCode() == http.StatusNotFound {
		return item{}, ErrorNotFound
	}
	if resp.IsError() {
		return item{}, errors.New(http.StatusText(resp.StatusCode()))
	}
	return i, nil
}

func (c *couchDBStorage) update(item item) error {
	current, err := c.read(item.ID)
	if err != nil {
		return err
	}

	item.Revision = current.Revision

	resp, err := resty.New().R().
		SetBody(item).
		Put(fmt.Sprintf("%s/%s", c.url, item.ID))
	if err != nil {
		return err
	}
	if resp.StatusCode() == http.StatusNotFound {
		return ErrorNotFound
	}
	if resp.IsError() {
		return errors.New(http.StatusText(resp.StatusCode()))
	}
	return nil
}

func (c *couchDBStorage) delete(id string) error {
	item, err := c.read(id)
	if err != nil {
		return err
	}

	resp, err := resty.New().R().
		SetQueryParam("rev", item.Revision).
		Delete(fmt.Sprintf("%s/%s", c.url, id))
	if err != nil {
		return err
	}
	if resp.IsError() {
		return errors.New(http.StatusText(resp.StatusCode()))
	}
	return nil
}
