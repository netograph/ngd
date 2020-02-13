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

func resolve(domain string) ([]string, error) {
	ma := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{
			dns.Question{
				Name:   domain + ".",
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
		return nil, fmt.Errorf(
			"failed to resolve after %d retries on %v: %s",
			len(resolvers),
			resolvers,
			domain,
		)
	}
	if len(in.Answer) == 0 {
		return nil, fmt.Errorf("empty DNS answer for %s", domain)
	}

	ips := []string{}
	for _, a := range in.Answer {
		switch v := a.(type) {
		case *dns.A:
			ips = append(ips, v.A.String())
		}
		//TODO: Eventually add IPv6 support
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records for %s", domain)
	}
	return ips, nil
}

func probeHttps(dialer *net.Dialer, domain string, debug bool) error {
	ips, err := resolve(domain)
	if err != nil {
		return err
	}
	var lastErr error
	for _, ip := range ips {
		if debug && lastErr != nil {
			fmt.Fprintln(os.Stderr, lastErr)
		}
		conn, err := tls.DialWithDialer(
			dialer,
			"tcp",
			ip+":443",
			&tls.Config{ServerName: domain},
		)
		if err != nil {
			lastErr = fmt.Errorf("%s on %s: %s", domain, ip, err)
			continue
		}
		if err := conn.Close(); err != nil {
			// we swallow this one, as long as establishment is working we are good.
			if debug {
				fmt.Fprintf(os.Stderr, "%s on %s: error on close, %s", domain, ip, err)
			}
		}
		return nil
	}
	return lastErr
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
					for domain := range ch {
						current := domain
						err := probeHttps(dialer, current, *debug)
						if err != nil {
							if *debug {
								fmt.Fprintln(os.Stderr, err)
							}
							current = "www." + domain
							err = probeHttps(dialer, current, *debug)
						}
						if err != nil {
							if *debug {
								fmt.Fprintln(os.Stderr, err)
							}
							fmt.Printf("http://%s/\n", domain)
						} else {
							fmt.Printf("https://%s/\n", current)
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
