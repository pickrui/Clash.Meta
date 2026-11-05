# fswatch

![Test](https://github.com/metacubex/fswatch/actions/workflows/test.yml/badge.svg)
![Lint](https://github.com/metacubex/fswatch/actions/workflows/lint.yml/badge.svg)
[![Go Reference](https://pkg.go.dev/badge/github.com/metacubex/fswatch.svg)](https://pkg.go.dev/github.com/metacubex/fswatch)

fswatch is a simple [fsnotify] wrapper to watch file updates correctly.

[fsnotify]: https://github.com/fsnotify/fsnotify

Install
---

```bash
go get github.com/metacubex/fswatch
```

Example
---

```go
package main

import (
	"log"

	"github.com/metacubex/fswatch"
)

func main() {
	var watchPath []string
	watchPath = append(watchPath, "/tmp/my_file")
	watcher, err := fswatch.NewWatcher(fswatch.Options{
		Path: watchPath,
		Callback: func(path string) {
			log.Println("file updated: ", path)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	// Block main goroutine forever.
	<-make(chan struct{})
}

```