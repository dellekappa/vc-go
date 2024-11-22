package storage

import (
	"errors"
	"github.com/dellekappa/kcms-go/spi/storage"
	"sync"
)

// CMSMockStore mock store.
type CMSMockStore struct {
	Store     map[string]DBEntry
	lock      sync.RWMutex
	ErrPut    error
	ErrGet    error
	ErrDelete error
}

// NewCMSMockStore new cms store instance.
func NewCMSMockStore() *CMSMockStore {
	return &CMSMockStore{
		Store: make(map[string]DBEntry),
	}
}

// Put stores the key and the record.
func (s *CMSMockStore) Put(k string, v []byte) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	if s.ErrPut != nil {
		return s.ErrPut
	}

	s.lock.Lock()
	s.Store[k] = DBEntry{
		Value: v,
	}
	s.lock.Unlock()

	return s.ErrPut
}

// Get fetches the record based on key.
func (s *CMSMockStore) Get(k string) ([]byte, error) {
	if s.ErrGet != nil {
		return nil, s.ErrGet
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	entry, ok := s.Store[k]
	if !ok {
		return nil, storage.ErrDataNotFound
	}

	return entry.Value, s.ErrGet
}

// Delete will delete record with k key.
func (s *CMSMockStore) Delete(k string) error {
	s.lock.Lock()
	delete(s.Store, k)
	s.lock.Unlock()

	return s.ErrDelete
}
