package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/fsnotify/fsnotify"
)

func monitorLog(ctx context.Context, logPath string) (_ <-chan string, err error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	if err = watcher.Add(logPath); err != nil {
		return
	}

	logFile, err := os.Open(logPath)
	if err != nil {
		return
	}
	if _, err = logFile.Seek(0, 2); err != nil {
		return
	}

	ch := make(chan string)
	go func() {
		defer logFile.Close()
		defer close(ch)
		for {
			select {
			case _, ok := <-watcher.Events:
				if !ok {
					return
				}
				for _, line := range tailRead(logFile) {
					ch <- line
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Printf("Error watching %s: %+v\n", logPath, err)
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

func tailRead(file *os.File) (lines []string) {
	newlines, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("Error tail reading %+v", err)
		return
	}
	scanner := bufio.NewScanner(bytes.NewBuffer(newlines))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return
}
