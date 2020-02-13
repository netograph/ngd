package cli

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

const ResolverRetries = 5

var Resolvers = []string{
	// Google
	"8.8.8.8",
	"8.8.4.4",
	// Cloudflare
	"1.1.1.1",
	"1.0.0.1",
	// Quad9
	"9.9.9.9",
	"149.112.112.112",
	// OpenDNS
	"208.67.222.222",
	"208.67.220.220",
}

func resolver() string {
	return Resolvers[rand.Int()%len(Resolvers)]
}

func resolve(dialer *net.Dialer, dom string, debug bool) (string, error) {
	ma := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{
			dns.Question{
				Name:   dom + ".",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			},
		},
	}
	c := &dns.Client{}
	var in *dns.Msg
	resolvers := []string{}
	for {
		var err error
		res := resolver()
		resolvers = append(resolvers, res)
		in, _, err = c.Exchange(ma, fmt.Sprintf("%s:53", res))
		if err == nil || len(resolvers) >= ResolverRetries {
			break
		}
		time.Sleep(100 * time.Duration(len(resolvers)) * time.Millisecond)
	}
	if in == nil {
		return "", fmt.Errorf(
			"failed to resolve after %d retries on %v: %s",
			len(resolvers),
			resolvers,
			dom,
		)
	}
	if len(in.Answer) == 0 {
		return "", errors.New("empty DNS answer")
	}

	ip := ""
	for _, a := range in.Answer {
		switch v := a.(type) {
		case *dns.A:
			ip = v.A.String()
		// TODO: AAAA records
		// TODO: Do we need to try all A/AAAA records? Not sure what the spec says.
		}
	}
	if ip == "" {
		return "", errors.New("no A record")
	}
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		ip+":443",
		&tls.Config{ServerName: dom},
	)
	if err != nil {
		return "", fmt.Errorf("%s on %s: %s", dom, ip, err)
		// TODO: Attempt to connect to :80 here and return http:// if successful.
	}
	if err := conn.Close(); err != nil {
		if debug {
			fmt.Fprintf(os.Stderr, "error on close: %s", err)
		}
	}
	return "https://" + dom + "/", nil
}

func domainsCommand() *cobra.Command {
	var concurrency *int
	var debug *bool
	cmd := &cobra.Command{
		Use:   "domains path",
		Short: "reads a domain file and emits clean URLs",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("usage: domains path")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			r := bufio.NewReader(f)
			log.SetOutput(ioutil.Discard)
			var wg sync.WaitGroup
			ch := make(chan string, *concurrency)
			for i := 0; i < *concurrency; i++ {
				dialer := &net.Dialer{
					Timeout:       10 * time.Second,
					FallbackDelay: -1,
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					for res := range ch {
						for _, dom := range []string{res, "www." + res} {
							url, err := resolve(dialer, dom, *debug)
							if err != nil {
								if *debug {
									fmt.Fprintf(os.Stderr, "%s,%s\n", dom, err)
								}
							} else {
								fmt.Printf("%s,%s\n", dom, url)
								break
							}
						}
					}
				}()
			}
			for true {
				t, _, _ := r.ReadLine()
				if len(t) == 0 {
					break
				}
				ch <- string(t)
			}
			close(ch)
			wg.Wait()
			return nil
		},
	}
	concurrency = cmd.Flags().Int(
		"concurrency", 10, "Concurrent resolvers",
	)
	debug = cmd.Flags().Bool(
		"debug", false, "Debugging output",
	)
	return cmd
}
