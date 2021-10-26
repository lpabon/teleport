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
	"io"
	"sync"

	log "github.com/sirupsen/logrus"
)

type clientStreams struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// Multiplexer maps multiple clients onto one server with information split up into stdin, stdout and stderr streams.
type Multiplexer struct {
	mu              sync.Mutex
	clientsModified chan struct{}
	clients         map[int]clientStreams
	nextID          int
}

// NewMultiplexer creates a new Multiplexer.
func NewMultiplexer() *Multiplexer {
	clientsModified := make(chan struct{})
	clientsModified <- struct{}{}

	return &Multiplexer{
		clientsModified: clientsModified,
		clients:         make(map[int]clientStreams),
	}
}

// AddClient takes a set of client streams and starts multiplexing information to them.
func (m *Multiplexer) AddClient(stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	client := clientStreams{stdin, stdout, stderr}
	id := m.nextID
	m.nextID += 1
	m.clients[id] = client

	m.clientsModified <- struct{}{}
	return id
}

func (m *Multiplexer) getStreams() ([]io.Reader, []io.Writer, []io.Writer) {
	var stdin []io.Reader
	var stdout []io.Writer
	var stderr []io.Writer

	for _, client := range m.clients {
		stdin = append(stdin, client.stdin)
		stdout = append(stdout, client.stdout)
		stderr = append(stderr, client.stderr)
	}

	return stdin, stdout, stderr
}

// RemoveClient removes a client, i.e disconnecting them.
func (m *Multiplexer) RemoveClient(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.clients, id)
	m.clientsModified <- struct{}{}
}

// Run takes a set of server streams and starts multiplexing them to the clients.
func (m *Multiplexer) Run(stdin io.Writer, stdout io.Reader, stderr io.Reader) {
	var stdinR io.Reader
	var stdoutW io.Writer
	var stderrW io.Writer
	notifier := make(chan struct{})

	for {
		<-m.clientsModified
		m.mu.Lock()

		stdinRArr, stdoutWArr, stderrWArr := m.getStreams()
		stdinR = io.MultiReader(stdinRArr...)
		stdoutW = io.MultiWriter(stdoutWArr...)
		stderrW = io.MultiWriter(stderrWArr...)

		m.mu.Unlock()
		close(notifier)
		notifier = make(chan struct{})

		go copyUntil(stdinR, stdin, notifier)
		go copyUntil(stdout, stdoutW, notifier)
		go copyUntil(stderr, stderrW, notifier)
	}
}

// Name the function signature for ease of use.
type readerFunc func(p []byte) (n int, err error)

// Although somewhat cryptic, this snipped implements io.Reader for any closure with the correct signature.
func (rf readerFunc) Read(p []byte) (n int, err error) { return rf(p) }

// copyUntil copies data from src to dst until the notifier channel is closed.
func copyUntil(src io.Reader, dst io.Writer, notifier chan struct{}) {
	_, err := io.Copy(dst, readerFunc(func(p []byte) (int, error) {
		select {
		case <-notifier:
			return 0, nil
		default:
			return src.Read(p)
		}
	}))

	if err != nil {
		log.Warn("failed to multiplex session stream: %v", err)
	}
}
