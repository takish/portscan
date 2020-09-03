package main

import (
	"fmt"
	"time"
	"github.com/anvie/port-scanner"
)

func main(){
	var host = "localhost"
	var portStart = 20
	var PortEnds = 10000

	// scan localhost with a 2 second timeout per port in 5 concurrent threads
	ps := portscanner.NewPortScanner(host, 2*time.Second, 5)


	// get opened port
	fmt.Printf("scanning port %d-%d...\n", portStart, PortEnds)

	openedPorts := ps.GetOpenedPort(portStart, PortEnds)

	for i := 0; i < len(openedPorts); i++ {
		port := openedPorts[i]
		fmt.Print(" ", port, " [open]")
		fmt.Println("  -->  ", ps.DescribePort(port))
	}
}