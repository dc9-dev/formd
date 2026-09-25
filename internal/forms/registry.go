package forms

import (
	"fmt"
	"sync/atomic"
)

// Registry holds the compiled forms served by the public endpoint. The admin
// panel replaces the whole map after every change; readers never lock.
type Registry struct {
	p atomic.Pointer[map[string]*Form]
}

func NewRegistry() *Registry {
	r := &Registry{}
	m := map[string]*Form{}
	r.p.Store(&m)
	return r
}

func (r *Registry) Get(id string) *Form { return (*r.p.Load())[id] }

// Load compiles all definitions. Forms that fail to compile are skipped (and
// therefore not served) and reported.
func (r *Registry) Load(defs []Definition) []error {
	m := make(map[string]*Form, len(defs))
	var errs []error
	for _, d := range defs {
		f, err := Compile(d)
		if err != nil {
			errs = append(errs, fmt.Errorf("form %q: %w", d.ID, err))
			continue
		}
		m[d.ID] = f
	}
	r.p.Store(&m)
	return errs
}
