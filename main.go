package main

import (
	"net"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/mrichman/godnsbl"
)

// result response
type result struct {
	IP    string `xml:"ip"`
	Spam  bool   `xml:"spam"`
	Score int    `xml:"score"`
}

func main() {
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
		}
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
		c.XML(http.StatusOK, _result)
	})
	r.Run() // listen and server on 0.0.0.0:8080
}
