package main

import (
	"net"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/golang-lru/simplelru"
	"github.com/mrichman/godnsbl"
)

// result response
type result struct {
	IP    string `xml:"ip"`
	Spam  bool   `xml:"spam"`
	Score int    `xml:"score"`
}

func main() {
	lru, _ := simplelru.NewLRU(1024, nil)
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{})
	})
	r.GET("/api/check.xml", func(c *gin.Context) {
		_result := result{}
		rawIP := c.Query("ip")
		ip := net.ParseIP(rawIP)
		if ip.To4() != nil {
			_result.IP = ip.String()
			cached, ok := lru.Get(rawIP)
			if !ok {
				wg := &sync.WaitGroup{}
				results := make([]godnsbl.Result, len(godnsbl.Blacklists))
				for i, source := range godnsbl.Blacklists {
					wg.Add(1)
					go func(i int, source string) {
						defer wg.Done()
						rbl := godnsbl.Lookup(source, rawIP)
						if len(rbl.Results) == 0 {
							results[i] = godnsbl.Result{}
						} else {
							results[i] = rbl.Results[0]
							_result.Score++
						}
					}(i, source)
				}
				if _result.Score > 0 {
					_result.Spam = true
				}
				lru.Add(rawIP, _result.Spam)
			} else {
				if cached == "true" {
					_result.Spam = true
				} else {
					_result.Spam = false
				}
			}
		}

		c.XML(http.StatusOK, _result)
	})
	r.Run() // listen and server on 0.0.0.0:8080
}
