package cli

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// spinnerFrames are braille dot animation frames.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner displays an animated spinner on stderr while a long-running
// operation is in progress.
//
// When stderr is not a TTY (e.g. CI logs, piped output), animation is
// suppressed and only plain-text status lines are printed.
//
// Example:
//
//	s := newSpinner("Downloading vulnerability database...")
//	s.Start()
//	err := doSlowWork()
//	if err != nil {
//	    s.Fail(fmt.Sprintf("❌ Failed: %v", err))
//	} else {
//	    s.Success("✅ Done!")
//	}
type Spinner struct {
	message string
	writer  *os.File
	isTTY   bool

	mu     sync.Mutex
	active bool
	quit   chan struct{}
	wg     sync.WaitGroup
}

// newSpinner creates a new Spinner with the given initial message.
// Call Start() to begin the animation.
func newSpinner(msg string) *Spinner {
	s := &Spinner{
		message: msg,
		writer:  os.Stderr,
	}
	// Detect TTY: animation only makes sense for interactive terminals.
	if fi, err := os.Stderr.Stat(); err == nil {
		s.isTTY = (fi.Mode() & os.ModeCharDevice) != 0
	}
	return s
}

// Start begins the spinner animation in a background goroutine.
// In non-TTY mode, prints the initial message immediately and returns.
func (s *Spinner) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active {
		return
	}
	s.active = true

	if !s.isTTY {
		fmt.Fprintf(s.writer, "%s\n", s.message)
		return
	}

	s.quit = make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		i := 0
		for {
			select {
			case <-s.quit:
				return
			default:
				s.mu.Lock()
				msg := s.message
				s.mu.Unlock()
				fmt.Fprintf(s.writer, "\r%s %s", spinnerFrames[i%len(spinnerFrames)], msg)
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

// UpdateMessage updates the spinner message while it is running.
func (s *Spinner) UpdateMessage(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.message = msg
	if !s.isTTY {
		fmt.Fprintf(s.writer, "%s\n", msg)
	}
}

// Success stops the spinner and prints a success message.
func (s *Spinner) Success(msg string) {
	s.stop(msg)
}

// Fail stops the spinner and prints a failure message.
func (s *Spinner) Fail(msg string) {
	s.stop(msg)
}

// stop halts the background goroutine and prints finalMsg on a clean line.
func (s *Spinner) stop(finalMsg string) {
	s.mu.Lock()
	wasActive := s.active
	s.active = false
	s.mu.Unlock()

	if !wasActive {
		return
	}

	if !s.isTTY {
		if finalMsg != "" {
			fmt.Fprintf(s.writer, "%s\n", finalMsg)
		}
		return
	}

	close(s.quit)
	s.wg.Wait()

	// \r moves to start of line; \033[K erases to end of line.
	if finalMsg != "" {
		fmt.Fprintf(s.writer, "\r\033[K%s\n", finalMsg)
	} else {
		fmt.Fprintf(s.writer, "\r\033[K")
	}
}
