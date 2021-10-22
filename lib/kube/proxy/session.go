/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxy

import (
	"sync"

	"github.com/google/uuid"
)

type SessionState int

const (
	SessionPending SessionState = 1
	SessionRunning SessionState = 2
)

// Participant stores all state for a session participant required for networking and permission checking.
type Participant struct {
	Context *authContext
}

// Session stores the state of an ongoing interactive session.
type Session struct {
	mu       sync.Mutex
	uuid     uuid.UUID
	owner    *Participant
	notifier chan struct{}

	// mutable, protected by lock
	state SessionState

	// mutable, protected by lock
	participants []*Participant

	// mutable, protected by lock
	multiplexer *Multiplexer
}

// NewSession creates a new Session with a given owner.
func NewSession(owner *Participant) *Session {
	participants := make([]*Participant, 0)
	participants = append(participants, owner)
	uuid, _ := uuid.NewRandom()

	return &Session{
		state:        SessionPending,
		uuid:         uuid,
		owner:        owner,
		participants: participants,
		notifier:     make(chan struct{}),
	}
}

// WaitOnStart adds the given participant to the list of session participants
// and waits for the session to transition to a running state.
func (s *Session) WaitOnStart(participant *Participant) {
	s.mu.Lock()
	s.participants = append(s.participants, participant)

	if s.state == SessionRunning {
		return
	}

	if sessionClearanceAcquired(s.participants) {
		s.state = SessionRunning
		s.multiplexer = NewMultiplexer()
		close(s.notifier)
		s.mu.Unlock()
	} else {
		s.mu.Unlock()
		_, open := <-s.notifier

		if open {
			panic("something is terribly wrong")
		}
	}
}

// Fetch the multiplexer of a given session.
func (s *Session) Multiplexer() *Multiplexer {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.multiplexer
}

// sessionClearanceAcquired determines if a set of participants
// fulfills the criteria to transition a session to a running state.
func sessionClearanceAcquired(participants []*Participant) bool {
	for _, participant := range participants {
		roles := participant.Context.User.GetRoles()

		for _, role := range roles {
			if role == "admin" {
				return true
			}
		}
	}

	return false
}
