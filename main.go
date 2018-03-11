package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/genuinetools/certok/version"
	"github.com/mitchellh/colorstring"
	"github.com/sirupsen/logrus"
)

const (
	// BANNER is what is printed for help/info output.
	BANNER = `               _        _
  ___ ___ _ __| |_ ___ | | __
 / __/ _ \ '__| __/ _ \| |/ /
| (_|  __/ |  | || (_) |   <
 \___\___|_|   \__\___/|_|\_\

 Check the validity and expiration dates of SSL certificates.
 Version: %s
 Build: %s

`

	defaultWarningDays = 30
)

var (
	days   int
	months int
	years  int

	all bool

	debug bool
	vrsn  bool
)

func init() {
	// parse flags
	flag.IntVar(&years, "years", 0, "Warn if the certificate will expire within this many years.")
	flag.IntVar(&months, "months", 0, "Warn if the certificate will expire within this many months.")
	flag.IntVar(&days, "days", 0, "Warn if the certificate will expire within this many days.")

	flag.BoolVar(&all, "all", false, "Show entire certificate chain, not just the first.")

	flag.BoolVar(&vrsn, "version", false, "print version and exit")
	flag.BoolVar(&vrsn, "v", false, "print version and exit (shorthand)")
	flag.BoolVar(&debug, "d", false, "run in debug mode")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, fmt.Sprintf(BANNER, version.VERSION, version.GITCOMMIT))
		flag.PrintDefaults()
	}

	flag.Parse()

	if vrsn {
		fmt.Printf("certok version %s, build %s", version.VERSION, version.GITCOMMIT)
		os.Exit(0)
	}

	// set log level
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// set the default warning days if not set already
	if years == 0 && months == 0 && days == 0 {
		days = defaultWarningDays
	}

}

func main() {
	args := flag.Args()

	// check if we are reading from a file or stdin
	var (
		scanner *bufio.Scanner
	)
	if len(args) == 0 {
		logrus.Debugf("no file passed, reading from stdin...")
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		f, err := os.Open(args[0])
		if err != nil {
			logrus.Fatalf("opening file %s failed: %v", args[0], err)
			os.Exit(1)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}

	// get the time now
	now := time.Now()
	twarn := now.AddDate(years, months, days)

	// create the writer
	w := tabwriter.NewWriter(os.Stdout, 20, 1, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSUBJECT\tISSUER\tALGO\tEXPIRES\tSUNSET DATE\tERROR")

	// create the WaitGroup
	var wg sync.WaitGroup
	for scanner.Scan() {
		wg.Add(1)
		h := scanner.Text()
		go func() {
			certs, err := checkHost(h, twarn)
			if err != nil {
				logrus.Warn(err)
			}
			for _, cert := range certs {
				sunset := ""
				if cert.sunset != nil {
					sunset = cert.sunset.date.Format("Jan 02, 2006")

				}
				expires := cert.expires
				if cert.warn {
					expires = colorstring.Color("[red]" + cert.expires + "[reset]")
				}
				error := cert.error
				if error != "" {
					error = colorstring.Color("[red]" + cert.error + "[reset]")
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", cert.name, cert.subject, cert.issuer, cert.algo, expires, sunset, error)
			}
			wg.Done()
		}()
	}
	// wait for all the goroutines to finish
	wg.Wait()
	// flush the writer
	w.Flush()
}

type host struct {
	name    string
	subject string
	algo    string
	issuer  string
	expires string
	warn    bool
	error   string
	sunset  *sunsetSignatureAlgorithm
}

func checkHost(h string, twarn time.Time) (map[string]host, error) {
	if !strings.Contains(h, ":") {
		// default to 443
		h += ":443"
	}
	c, err := tls.Dial("tcp", h, nil)
	if err != nil {
		switch cerr := err.(type) {
		case x509.CertificateInvalidError:
			ht := createHost(h, twarn, cerr.Cert)
			ht.error = err.Error()
			return map[string]host{
				string(cerr.Cert.Signature): ht,
			}, nil
		case x509.UnknownAuthorityError:
			ht := createHost(h, twarn, cerr.Cert)
			ht.error = err.Error()
			return map[string]host{
				string(cerr.Cert.Signature): ht,
			}, nil
		case x509.HostnameError:
			ht := createHost(h, twarn, cerr.Certificate)
			ht.error = err.Error()
			return map[string]host{
				string(cerr.Certificate.Signature): ht,
			}, nil
		}
		return nil, fmt.Errorf("tcp dial %s failed: %v", h, err)
	}
	defer c.Close()

	certs := make(map[string]host)
	for _, chain := range c.ConnectionState().VerifiedChains {
		for n, cert := range chain {
			if _, checked := certs[string(cert.Signature)]; checked {
				continue
			}
			if !all && n >= 1 {
				continue
			}

			ht := createHost(h, twarn, cert)

			certs[string(cert.Signature)] = ht
		}
	}

	return certs, nil
}

func createHost(name string, twarn time.Time, cert *x509.Certificate) host {
	host := host{
		name:    name,
		subject: cert.Subject.CommonName,
		issuer:  cert.Issuer.CommonName,
		algo:    cert.SignatureAlgorithm.String(),
	}

	// check the expiration
	if twarn.After(cert.NotAfter) {
		host.warn = true
	}
	expiresIn := int64(time.Until(cert.NotAfter).Hours())
	if expiresIn <= 48 {
		host.expires = fmt.Sprintf("%d hours", expiresIn)
	} else {
		host.expires = fmt.Sprintf("%d days", expiresIn/24)
	}

	// Check the signature algorithm, ignoring the root certificate.
	if alg, exists := sunsetSignatureAlgorithms[cert.SignatureAlgorithm]; exists {
		if cert.NotAfter.Equal(alg.date) || cert.NotAfter.After(alg.date) {
			host.warn = true
		}
		host.sunset = &alg
	}

	return host
}
