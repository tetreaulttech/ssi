package wallet

type inMemoryStorage struct {
	items map[string]item
}

func NewInMemoryStorage() Storage {
	ims := &inMemoryStorage{}
	ims.items = make(map[string]item)
	return ims
}

func (i *inMemoryStorage) create(item item) error {
	i.items[item.ID] = item
	return nil
}

func (i *inMemoryStorage) read(id string) (item, error) {
	if item, ok := i.items[id]; ok {
		return item, nil
	}
	return item{}, ErrorNotFound
}

func (i *inMemoryStorage) update(item item) error {
	i.items[item.ID] = item
	return nil
}

func (i *inMemoryStorage) delete(id string) error {
	delete(i.items, id)
	return nil
}
