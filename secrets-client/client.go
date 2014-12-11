package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/tehmaze-labs/secrets/key"
	"github.com/tehmaze-labs/secrets/secret"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}

func usage() {
	fmt.Printf("usage:\n\n  %s [<options>] <command>\n", os.Args[0])
	println(`
commands:

  secrets-client generate
  secrets-client ls [<group>]
  secrets-client cat <group> <key>
  secrets-client put <group> <key> <file>

options:
`)
	flag.PrintDefaults()
	os.Exit(1)
}

type Client struct {
	http.Client
	BaseURL string
}

func (c *Client) readJSON(resp *http.Response, v interface{}) (err error) {
	if err = c.readStatus(resp); err != nil {
		return err
	}
	var body []byte
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		return err
	}
	if err = json.Unmarshal(body, &v); err != nil {
		return err
	}
	return nil
}
func (c *Client) readStatus(resp *http.Response) error {
	switch resp.StatusCode {
	case 403:
		return errors.New(`not authorized`)
	case 404:
		return errors.New(`not found`)
	case 500:
		return errors.New(`internal server error`)
	default:
		if resp.StatusCode != 200 {
			return fmt.Errorf("server replied with %q", resp.Status)
		}
	}
	return nil
}

func (c *Client) GetJSON(rawurl string, v interface{}) error {
	url, err := url.Parse(rawurl)
	if err != nil {
		return err
	}
	if url.Scheme == "" {
		rawurl = c.BaseURL + rawurl
	}
	resp, err := c.Get(rawurl)
	if err != nil {
		return err
	}
	return c.readJSON(resp, v)
}

func (c *Client) PutJSON(rawurl string, v interface{}) error {
	url, err := url.Parse(rawurl)
	if err != nil {
		return err
	}
	if url.Scheme == "" {
		rawurl = c.BaseURL + rawurl
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	buff := bytes.NewBuffer(data)
	req, err := http.NewRequest("PUT", rawurl, buff)
	if err != nil {
		return err
	}
	log.Printf("PUT %s (%d)\n", rawurl, len(data))
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	log.Println("read status...")
	return c.readStatus(resp)
}

func NewClient(baseURL string) *Client {
	c := &Client{
		BaseURL: baseURL,
	}
	c.Client.Transport = &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) { return nil, nil },
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return c
}

type groupInfo map[string][]byte

func main() {
	var keyFile string
	var baseURL string
	flag.StringVar(&keyFile, "k", "testdata/client.box", "box key file")
	flag.StringVar(&baseURL, "u", "https://:6443/", "server URL")
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
	}

	k, err := key.Load(keyFile)
	if err != nil {
		panic(err)
	}

	if strings.HasSuffix(baseURL, "/") {
		baseURL = baseURL[:len(baseURL)-1]
	}

	client := NewClient(baseURL)
	switch flag.Args()[0] {
	case "ls":
		if flag.NArg() == 1 {
			var groups []string
			if err = client.GetJSON("/group/", &groups); err != nil {
				fatal(err)
			}
			if len(groups) == 0 {
				fatal(errors.New(`no groups found`))
			}
			for _, group := range groups {
				fmt.Println(group)
			}
		} else if flag.NArg() == 2 {
			var data map[string][]string
			url := fmt.Sprintf("/group/%s/data/", url.QueryEscape(flag.Arg(1)))
			if err = client.GetJSON(url, &data); err != nil {
				fatal(err)
			}
			if len(data) == 0 {
				fatal(errors.New(`no data found`))
			}
			for _, item := range data["keys"] {
				fmt.Println(item)
			}
		} else {
			usage()
		}

	case "cat":
		if flag.NArg() != 3 {
			usage()
		}
		dataUrl := fmt.Sprintf("/group/%s/data/%s/",
			url.QueryEscape(flag.Arg(1)),
			url.QueryEscape(flag.Arg(2)))
		var secret secret.Secret
		if err = client.GetJSON(dataUrl, &secret); err != nil {
			fatal(err)
		}
		data, err := secret.Decrypt(k)
		if err != nil {
			fatal(err)
		}
		fmt.Fprint(os.Stdout, string(data))

	case "put":
		if flag.NArg() != 3 && flag.NArg() != 4 {
			usage()
		}

		// Get group keys
		groupUrl := fmt.Sprintf("/group/%s/", url.QueryEscape(flag.Arg(1)))
		var group groupInfo
		if err = client.GetJSON(groupUrl, &group); err != nil {
			panic(err)
		}
		var keys = []*key.Key{}
		for node, pub := range group {
			log.Printf("signing for node %q\n", node)
			keys = append(keys, key.ParsePublicKey(pub))
		}

		// Get data to store
		var data []byte
		if flag.NArg() == 3 {
			data, err = ioutil.ReadAll(os.Stdin)
		} else {
			data, err = ioutil.ReadFile(flag.Arg(3))
		}
		if err != nil {
			panic(err)
		}

		// Construct group secret and send it to the group
		secret := secret.NewGroupSecret(data, k, keys)
		if data, err = secret.Marshal(); err != nil {
			panic(err)
		}
		url := fmt.Sprintf("%sdata/%s/", groupUrl, url.QueryEscape(flag.Arg(2)))
		if err = client.PutJSON(url, secret); err != nil {
			fatal(err)
		}
		println("done!")
	}
}
