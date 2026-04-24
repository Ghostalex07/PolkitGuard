package watcher

import (
	"fmt"
	"os"
	"time"

	"github.com/Ghostalex07/PolkitGuard/internal/scanner"
)

type Watcher struct {
	paths   []string
	interval time.Duration
	onChange func(string)
	running bool
}

type ChangeCallback func(path string)

func NewWatcher(paths []string, interval time.Duration) *Watcher {
	if interval == 0 {
		interval = 5 * time.Second
	}
	return &Watcher{
		paths:     paths,
		interval: interval,
		running:  false,
	}
}

func (w *Watcher) Start(callback ChangeCallback) error {
	if w.running {
		return fmt.Errorf("watcher already running")
	}

	w.running = true
	w.onChange = callback
	go w.run()
	return nil
}

func (w *Watcher) Stop() {
	w.running = false
}

func (w *Watcher) run() {
	oldFiles := map[string]os.FileInfo{}

	for w.running {
		for _, path := range w.paths {
			s := scanner.NewScanner(nil)
			newFiles, err := s.ScanDirectory(path)
			if err != nil {
				continue
			}

			for _, file := range newFiles {
				info, err := os.Stat(file)
				if err != nil {
					continue
				}

				oldInfo, exists := oldFiles[file]
				if !exists || info.ModTime().After(oldInfo.ModTime()) {
					if w.onChange != nil {
						w.onChange(file)
					}
				}
				oldFiles[file] = info
			}
		}
		time.Sleep(w.interval)
	}
}

func (w *Watcher) IsRunning() bool {
	return w.running
}