package main

import (
	"strings"
	"os"
)

//TODO: Implement regular interval progress bars

// type progFunc func(current int, total int) float64

func ProgressBar(current int, total int) {
	progressPortions := current * 20 / total
	printProgress(progressPercentage)
}

func printProgress(portions int) {
	var progressBar strings.Builder
	progressBar.WriteString("[")
	for block in range 20 {
		if block <= progressPortions {
			progressBar.WriteString("■")
		} else {
			progressBar.WriteString("□")
		}
	}
	progressBar.WriteString("]")
	out.Writeln("\n<info>" + progressBar.String() + "</info>")
}

func main() {
	ProgressBar(0, 20)
	ProgressBar(10, 20)
	ProgressBar(20, 500)
}