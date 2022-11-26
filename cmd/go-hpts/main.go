package main

import (
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var (
	Verbose      = false
	Socks5Server = ""

	errAuthFailed          = errors.New("socks server auth failed")
	errAuthMethod          = errors.New("socks server required username/password auth")
	errUnsupportAuthMethod = errors.New("socks server required auth method not support now")
	errConnection          = errors.New("socks server return connection failure")
	errServerEntry         = errors.New("socks server url is invaild")
)

const (
	SocksVer5       = 0x05
	SocksCmdConnect = 0x01
	RSV             = 0x00
	// Auth Method
	NoAuthMethod               = 0x00
	UsernamePasswordAuthMethod = 0x02
	// Addr Type
	Socks5IP4    = 0x01
	Socks5IP6    = 0x04
	socks5Domain = 0x03
)

func ifHttpRequest(scheme string) bool {
	if scheme == "http" {
		return true
	}
	return false
}

func Socks5Handshake(r *http.Request) (net.Conn, error) {
	u, err := url.Parse(Socks5Server)
	if err != nil {
		return nil, err
	}
	dailAddr := u.Host
	if u.Port() == "" {
		return nil, errServerEntry
	}
	dest_conn, err := net.Dial("tcp", dailAddr)
	if err != nil {
		return nil, err
	}
	read_buf := make([]byte, 64)
	write_buf := make([]byte, 0, 64)
	// Provides 2 Auth METHODS:
	//   X'00' NO AUTHENTICATION REQUIRED
	//   X'02' USERNAME/PASSWORD
	dest_conn.Write([]byte{SocksVer5, 2, NoAuthMethod, UsernamePasswordAuthMethod})
	io.ReadAtLeast(dest_conn, read_buf, 2)
	// RequestMethod
	switch read_buf[1] {
	case 0:
		// NoAuth
	case 2:
		// Username/PasswordAuth
		username := u.User.Username()
		password, flag := u.User.Password()
		if username == "" {
			return nil, errAuthMethod
		}
		write_buf = append(write_buf, SocksVer5)
		write_buf = append(write_buf, uint8(len(username)))
		write_buf = append(write_buf, username...)
		if !flag {
			return nil, errServerEntry
		}
		write_buf = append(write_buf, uint8(len(password)))
		write_buf = append(write_buf, password...)
		dest_conn.Write(write_buf)
		io.ReadAtLeast(dest_conn, read_buf, 2)
		if read_buf[1] != 0 {
			return nil, errAuthFailed
		}
	default:
		return nil, errUnsupportAuthMethod
	}
	write_buf = write_buf[:0]
	write_buf = append(write_buf, SocksVer5, SocksCmdConnect, RSV)
	hostname := r.URL.Hostname()
	if ip := net.ParseIP(hostname); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			//socks5IP4
			write_buf = append(write_buf, Socks5IP4)
			write_buf = append(write_buf, []byte(v4)...)
		} else {
			//socks5IP6
			write_buf = append(write_buf, Socks5IP6)
			write_buf = append(write_buf, []byte(ip)...)
		}
	} else {
		//socks5Domain
		write_buf = append(write_buf, socks5Domain)
		write_buf = append(write_buf, byte(len(hostname)))
		write_buf = append(write_buf, hostname...)
	}
	port := 443
	if port_str := r.URL.Port(); port_str != "" {
		port, _ = strconv.Atoi(port_str)
	}
	write_buf = append(write_buf, byte(port>>8), byte(port))
	dest_conn.Write(write_buf)
	io.ReadAtLeast(dest_conn, read_buf, 2)
	if read_buf[1] != 0 {
		return nil, errConnection
	}
	if Verbose {
		switch read_buf[3] {
		case Socks5IP6:
			// ipv6 = 16 * 8bit = 128
			ip := net.IP(read_buf[4 : 4+16])
			port := int(read_buf[4+16])<<8 + int(read_buf[4+16+1])
			log.Printf("Socks Server Replies @ [%s]:%d \n", ip.String(), port)
		case Socks5IP4:
			// ipv4 = 4 * 8bit = 32
			ip := net.IP(read_buf[4 : 4+4])
			port := int(read_buf[4+4])<<8 + int(read_buf[4+4+1])
			log.Printf("Socks Server Replies @ %s:%d \n", ip.String(), port)
		}
	}
	return dest_conn, nil
}

func HandleHttp(w http.ResponseWriter, r *http.Request) {
	if Verbose {
		log.Printf("New Http Request @ %s \n", r.Host)
	}
	u, err := url.Parse(Socks5Server)
	if err != nil {
		log.Printf("Error on Http Request @ %s: %s \n", r.Host, err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ProxyTransport := http.Transport{
		Proxy: http.ProxyURL(u),
		Dial: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	response, err := ProxyTransport.RoundTrip(r)
	if err != nil {
		log.Printf("Error on Http Request @ %s: %s \n", r.Host, err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
}

func HandleHttps(w http.ResponseWriter, r *http.Request) {
	if Verbose {
		log.Printf("New Https Request @ %s \n", r.Host)
	}
	dest_conn, err := Socks5Handshake(r)
	if err != nil {
		log.Printf("Error on Https Request @ %s: %s \n", r.Host, err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Error on Https Request @ %s: %s \n", r.Host, err.Error())
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Error on Https Request @ %s: %s \n", r.Host, err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	_, err = io.WriteString(client_conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		log.Printf("Error on Https Request @ %s: %s \n", r.Host, err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	go transfer(client_conn, dest_conn)
	go transfer(dest_conn, client_conn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func main() {

	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	socks5Server := flag.String("s", "socks5://127.0.0.1:8888", "socks5 server url")
	port := flag.String("p", "6699", "http proxy listen port")
	flag.Parse()

	Verbose = *verbose
	Socks5Server = *socks5Server

	log.Printf("Listen Port: %s \n", *port)

	server := &http.Server{
		Addr: ":" + *port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ifHttpRequest(r.URL.Scheme) {
				HandleHttp(w, r)
				return
			}
			HandleHttps(w, r)
		}),
	}
	server.ListenAndServe()
}
