// Command fakexray stands in for xray-core in the supervisor's tests.
//
// It exists because what the supervisor does is entirely about a real child process:
// waiting for it to listen, noticing it die, killing it when it will not go, rolling a
// configuration back when the process refuses to start. A mocked process would test the
// mock. This binary is a real one that can be told to misbehave on purpose.
//
// It accepts the same command line the supervisor uses:
//
//	fakexray version
//	fakexray run -test -config <path>
//	fakexray run -config <path>
//
// Behaviour is driven by fields the test puts in the configuration:
//
//	"fake_reject":  true  -> `run -test` fails, as an invalid configuration does
//	"fake_crash":   true  -> `run` exits immediately, as an unstartable one does
//	"fake_no_listen": true -> `run` stays up but never listens
//	"fake_exit_after_ms": N -> `run` serves, then dies on its own
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type config struct {
	Inbounds []struct {
		Tag    string `json:"tag"`
		Listen string `json:"listen"`
		Port   int    `json:"port"`
	} `json:"inbounds"`

	Reject       bool `json:"fake_reject"`
	Crash        bool `json:"fake_crash"`
	NoListen     bool `json:"fake_no_listen"`
	ExitAfterMS  int  `json:"fake_exit_after_ms"`
	StartDelayMS int  `json:"fake_start_delay_ms"`
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fail("no command")
	}

	switch args[0] {
	case "version":
		fmt.Println("Xray 26.3.27 (Xray, Penetrates Everything.) fake")
		fmt.Println("A unified platform for anti-censorship.")
		return
	case "run":
		run(args[1:])
	default:
		fail("unknown command " + args[0])
	}
}

func run(args []string) {
	test := false
	path := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-test":
			test = true
		case "-config", "-c":
			if i+1 >= len(args) {
				fail("-config needs a value")
			}
			i++
			path = args[i]
		}
	}
	if path == "" {
		fail("no -config given")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		fail("read config: " + err.Error())
	}

	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		fail("config is not valid json: " + err.Error())
	}

	if cfg.Reject {
		fail("this configuration is rejected on purpose")
	}
	if test {
		// Matches xray, which prints this and exits zero.
		fmt.Println("Configuration OK.")
		return
	}

	if cfg.Crash {
		fail("refusing to start on purpose")
	}
	if cfg.StartDelayMS > 0 {
		time.Sleep(time.Duration(cfg.StartDelayMS) * time.Millisecond)
	}

	if !cfg.NoListen {
		listener, err := net.Listen("tcp", endpoint(cfg))
		if err != nil {
			fail("listen: " + err.Error())
		}
		defer listener.Close()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}

	if cfg.ExitAfterMS > 0 {
		time.Sleep(time.Duration(cfg.ExitAfterMS) * time.Millisecond)
		fail("exiting on purpose after " + strconv.Itoa(cfg.ExitAfterMS) + "ms")
	}

	// Xray runs until it is told to stop, and so does this.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}

func endpoint(cfg config) string {
	for _, inbound := range cfg.Inbounds {
		if inbound.Tag == "api" && inbound.Port != 0 {
			host := inbound.Listen
			if host == "" {
				host = "127.0.0.1"
			}
			return net.JoinHostPort(host, strconv.Itoa(inbound.Port))
		}
	}
	return "127.0.0.1:0"
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "fakexray: "+message)
	os.Exit(1)
}
