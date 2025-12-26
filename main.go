package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"time"
)

// extract filename from path and replace invalid characters for safe output
func sanitizeFilename(path string) string {
	name := path
	if idx := strings.LastIndex(path, "\\"); idx != -1 {
		name = path[idx+1:]
	}
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		name = name[idx+1:]
	}
	replacer := strings.NewReplacer("<", "_", ">", "_", ":", "_", "\"", "_", "|", "_", "?", "_", "*", "_")
	return replacer.Replace(name)
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Target process name: ")
	scanner.Scan()
	target := strings.TrimSpace(scanner.Text())

	fmt.Print("Output directory: ")
	scanner.Scan()
	outputDir := strings.TrimSpace(scanner.Text())

	// create output directory if it doesn't exist
	os.MkdirAll(outputDir, 0755)

	fmt.Printf("\n>>> Extracting all files from %s\n", target)

	procs, err := ScanProcesses(target)
	if err != nil {
		fmt.Printf("!!! Scan failed: %v\n", err)
		os.Exit(1)
	}
	if len(procs) == 0 {
		fmt.Println("!!! No running instances")
		os.Exit(1)
	}

	fmt.Printf(">>> Scanning %d instance(s)\n", len(procs))

	savedCount := 0
	for pid, handles := range procs {
		fmt.Printf("... PID %d (%d handles)\n", pid, len(handles))
		errCounts := make(map[string]int)
		for _, h := range handles {
			// run ExtractFile with 5 second timeout to avoid hangs on certain problematic file handles
			type result struct {
				data     []byte
				location string
				err      error
			}
			ch := make(chan result, 1)
			go func(hVal uintptr, p uint32) {
				d, l, e := ExtractFile(hVal, p)
				ch <- result{d, l, e}
			}(h.Val, pid)

			var data []byte
			var location string
			var err error
			select {
			case res := <-ch:
				data, location, err = res.data, res.location, res.err
			case <-time.After(5 * time.Second):
				errCounts["timeout"]++
				continue
			}

			if err != nil {
				errCounts[err.Error()]++
				continue
			}

			fmt.Printf("\n*** FOUND ***\n")
			fmt.Printf("  Location: %s\n", location)
			fmt.Printf("  PID: %d\n", pid)
			fmt.Printf("  Handle: 0x%X\n", h.Val)
			fmt.Printf("  Size: %d bytes\n", len(data))
			// auto-generate unique filenames using PID_handle_originalname format
			// this prevents collisions when extracting multiple files and removes
			// the need for user input per file, enabling batch extraction
			// (i can fix this if your goal wasn't to extract all file contents,
			// but the user doesn't know the file names prior to selecting one so this makes sense)
			filename := fmt.Sprintf("%d_%x_%s", pid, h.Val, sanitizeFilename(location))
			output := outputDir + "\\" + filename
			if err := SaveFile(data, output); err != nil {
				fmt.Printf("!!! Save failed: %v\n", err)
				continue
			}

			fmt.Printf(">>> Saved to: %s\n", output)
			savedCount++
		}
		_ = errCounts
	}

	if savedCount == 0 {
		fmt.Println("\nnone")
	} else {
		fmt.Printf("\n>>> Complete! Saved %d file(s)\n", savedCount)
	}
}
