package rules

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Store 保存所有已发布的规则集版本，当前版本通过原子指针发布。
// 每次判定先 Load 当前快照；发布/回滚只替换指针，正在进行的
// 判定始终持有同一个不可变快照，绝不会混用新旧规则。
type Store struct {
	current atomic.Pointer[RuleSet]

	mu      sync.RWMutex
	history map[string]*RuleSet
	order   []string
}

func NewStore() *Store {
	return &Store{history: map[string]*RuleSet{}}
}

var (
	ErrVersionExists = errors.New("ruleset version already exists")
	ErrVersionAbsent = errors.New("ruleset version not found")
)

// Publish 发布一个新版本并原子生效。版本号必须唯一，
// 历史决策引用的旧版本内容永远不会被覆盖。
func (s *Store) Publish(rs *RuleSet) error {
	if err := rs.Validate(); err != nil {
		return fmt.Errorf("invalid ruleset: %w", err)
	}
	if rs.ActivatedAt.IsZero() {
		rs.ActivatedAt = time.Now()
	}
	rs.Hash()

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.history[rs.Version]; exists {
		return ErrVersionExists
	}
	s.history[rs.Version] = rs
	s.order = append(s.order, rs.Version)
	s.current.Store(rs)
	return nil
}

// Current 返回当前生效的规则集快照（只读，禁止修改）。
func (s *Store) Current() (*RuleSet, error) {
	rs := s.current.Load()
	if rs == nil {
		return nil, ErrVersionAbsent
	}
	return rs, nil
}

// Get 按版本号取出历史快照，用于重放与审计。
func (s *Store) Get(version string) (*RuleSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rs, ok := s.history[version]
	if !ok {
		return nil, ErrVersionAbsent
	}
	return rs, nil
}

// Rollback 把当前版本指针切回任一已发布的历史版本（内容不复制、不改写）。
// 回滚只影响之后的新判定，历史决策记录仍指向其原版本，结论不变。
func (s *Store) Rollback(version string) (*RuleSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, ok := s.history[version]
	if !ok {
		return nil, ErrVersionAbsent
	}
	s.current.Store(rs)
	return rs, nil
}

// Versions 按发布顺序返回所有版本号。
func (s *Store) Versions() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}
