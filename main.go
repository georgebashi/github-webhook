package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type Payload struct {
	Ref string
}

func main() {

	var crt string
	var key string
	var secret string
	var port int

	flag.StringVar(&crt, "crt", "", "Path to server.crt")
	flag.StringVar(&key, "key", "", "Path to server.key")
	flag.StringVar(&secret, "secret", "", "Payload signing secret")
	flag.IntVar(&port, "port", 8080, "Port to listen on")
	flag.Parse()

	if crt == "" || key == "" || secret == "" {
		fmt.Fprintln(os.Stderr, "You must specify -crt, -key and -secret!")
		flag.PrintDefaults()
		return
	}

	http.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
		payload, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Couldn't read body")
			return
		}

		sig_headers, ok := r.Header["X-Hub-Signature"]
		if !ok {
			fmt.Fprintln(os.Stderr, "Couldn't find signiture header, did you set a secret?")
			return
		}
		sig := strings.Replace(sig_headers[0], "sha1=", "", 1)
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write(payload)
		expected := mac.Sum(nil)
		actual, err := hex.DecodeString(sig)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Couldn't decode sig")
			return
		}

		if !hmac.Equal(actual, expected) {
			fmt.Fprintf(os.Stderr, "Incorrect signiture, check it is set correctly both ends (was %s, should be %s)\n", sig, expected)
			return
		}

		var p Payload
		err = json.Unmarshal(payload, &p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Couldn't unmarshal JSON")
			return
		}

		branch := strings.Replace(p.Ref, "refs/heads/", "", 1)

		fmt.Fprintln(os.Stderr, branch)
	})

	log.Fatal(http.ListenAndServeTLS(":"+strconv.Itoa(port), crt, key, nil))

}
