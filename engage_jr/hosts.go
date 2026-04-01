package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	reIPRange = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$`)
	reCIDR    = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$`)
	rePlainIP = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	reHTTP    = regexp.MustCompile(`^https?://`)
)

// cidrWarnThreshold is the maximum number of addresses to expand without warning.
const cidrWarnThreshold = 65536

// hostStats is returned by processHostFile to report what was written.
type hostStats struct {
	Unique int // total unique entries written to hosts
	HTTP   int // entries written to http_hosts
}

type hostFiles struct {
	hosts     *os.File
	hostsW    *bufio.Writer
	noHTTP    *os.File
	noHTTPW   *bufio.Writer
	withHTTP  *os.File
	withHTTPW *bufio.Writer
	seen      map[string]struct{}
	httpCount int
}

// addHost writes host to the hosts file, skipping duplicates.
func (hf *hostFiles) addHost(host string) {
	if _, exists := hf.seen[host]; exists {
		logDebug("skipping duplicate: %s", host)
		return
	}
	hf.seen[host] = struct{}{}
	fmt.Fprintln(hf.hostsW, host)
}

// addHTTPHost writes the original URL to http_hosts and the stripped hostname
// to both hosts and nohttp_hosts, deduplicating by stripped hostname.
func (hf *hostFiles) addHTTPHost(url, stripped string) {
	if _, exists := hf.seen[stripped]; exists {
		logDebug("skipping duplicate: %s", stripped)
		return
	}
	hf.seen[stripped] = struct{}{}
	hf.httpCount++
	fmt.Fprintln(hf.withHTTPW, url)
	fmt.Fprintln(hf.hostsW, stripped)
	fmt.Fprintln(hf.noHTTPW, stripped)
}

// flush flushes all buffered writers. Must be called before close to ensure
// writes are not lost silently on disk-full or I/O errors.
func (hf *hostFiles) flush() error {
	if err := hf.hostsW.Flush(); err != nil {
		return fmt.Errorf("flushing hosts: %w", err)
	}
	if err := hf.noHTTPW.Flush(); err != nil {
		return fmt.Errorf("flushing nohttp_hosts: %w", err)
	}
	if err := hf.withHTTPW.Flush(); err != nil {
		return fmt.Errorf("flushing http_hosts: %w", err)
	}
	return nil
}

func (hf *hostFiles) close() {
	hf.hosts.Close()
	hf.noHTTP.Close()
	hf.withHTTP.Close()
}

// processHostFile reads the host file at src and writes normalised host lists
// into destDir as: hosts, nohttp_hosts, http_hosts. Returns stats about what
// was written for reporting and metadata purposes.
func processHostFile(src, destDir string) (hostStats, error) {
	f, err := os.Open(src)
	if err != nil {
		return hostStats{}, fmt.Errorf("could not open host file: %w", err)
	}
	defer f.Close()

	if dryRun {
		logInfo("[dry-run] would process host file %s → %s/{hosts,nohttp_hosts,http_hosts}", src, destDir)
		return hostStats{}, nil
	}

	hf, err := openHostFiles(destDir)
	if err != nil {
		return hostStats{}, err
	}
	defer hf.close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := classifyAndWrite(line, hf); err != nil {
			logWarn("skipping %q: %v", line, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return hostStats{}, err
	}

	if err := hf.flush(); err != nil {
		return hostStats{}, err
	}

	return hostStats{
		Unique: len(hf.seen),
		HTTP:   hf.httpCount,
	}, nil
}

func classifyAndWrite(host string, hf *hostFiles) error {
	switch {
	case reHTTP.MatchString(host):
		hf.addHTTPHost(host, stripHTTP(host))

	case reIPRange.MatchString(host):
		ips, err := expandRange(host)
		if err != nil {
			return err
		}
		for _, ip := range ips {
			hf.addHost(ip)
		}

	case reCIDR.MatchString(host):
		ips, err := expandCIDR(host)
		if err != nil {
			return err
		}
		for _, ip := range ips {
			hf.addHost(ip)
		}

	case rePlainIP.MatchString(host):
		if net.ParseIP(host) == nil {
			return fmt.Errorf("invalid IP address: %s", host)
		}
		hf.addHost(host)

	default:
		hf.addHost(host)
	}
	return nil
}

func stripHTTP(host string) string {
	host = reHTTP.ReplaceAllString(host, "")
	if i := strings.Index(host, "/"); i != -1 {
		host = host[:i]
	}
	return host
}

// expandRange handles the format 10.10.10.1-10 → [10.10.10.1 ... 10.10.10.10].
func expandRange(host string) ([]string, error) {
	m := reIPRange.FindStringSubmatch(host)
	if m == nil {
		return nil, fmt.Errorf("invalid IP range: %s", host)
	}
	prefix := m[1]
	start, _ := strconv.Atoi(m[2])
	end, _ := strconv.Atoi(m[3])
	if start > end {
		return nil, fmt.Errorf("range start %d exceeds end %d in %s", start, end, host)
	}
	if end > 255 {
		return nil, fmt.Errorf("range end %d exceeds 255 in %s", end, host)
	}
	ips := make([]string, 0, end-start+1)
	for i := start; i <= end; i++ {
		ips = append(ips, fmt.Sprintf("%s%d", prefix, i))
	}
	return ips, nil
}

// expandCIDR enumerates every IP in the network using the stdlib net package.
// Warns if the network is larger than cidrWarnThreshold addresses.
func expandCIDR(cidr string) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}

	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	if hostBits > 16 {
		total := 1 << uint(hostBits)
		logWarn("%s expands to %d addresses — this may take a while", cidr, total)
	}

	current := ip.Mask(network.Mask)
	var ips []string
	for ; network.Contains(current); incrementIP(current) {
		ips = append(ips, current.String())
	}
	return ips, nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func openHostFiles(dir string) (*hostFiles, error) {
	open := func(name string) (*os.File, error) {
		return os.OpenFile(
			filepath.Join(dir, name),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0644,
		)
	}

	hosts, err := open("hosts")
	if err != nil {
		return nil, err
	}
	noHTTP, err := open("nohttp_hosts")
	if err != nil {
		hosts.Close()
		return nil, err
	}
	withHTTP, err := open("http_hosts")
	if err != nil {
		hosts.Close()
		noHTTP.Close()
		return nil, err
	}

	return &hostFiles{
		hosts:     hosts,
		hostsW:    bufio.NewWriter(hosts),
		noHTTP:    noHTTP,
		noHTTPW:   bufio.NewWriter(noHTTP),
		withHTTP:  withHTTP,
		withHTTPW: bufio.NewWriter(withHTTP),
		seen:      make(map[string]struct{}),
	}, nil
}
