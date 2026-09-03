package web

import (
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Listen serves handler on the given port. A nil handler is rejected so the
// process-wide http.DefaultServeMux (where expvar/pprof register themselves)
// is never exposed on the public listener.
func Listen(port int, handler http.Handler) {

	if handler == nil {
		log.Fatal("web.Listen: handler must not be nil")
	}

	sock, err := net.Listen("tcp", ":"+strconv.Itoa(port))

	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	//start listening
	go func() {
		err := server.Serve(sock)
		if err != nil {
			log.Fatal(err)
		}
	}()

}
