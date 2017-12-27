package main

import (
	"strings"
	"crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
)

func main() {
	// stringsVal := ComputeHmac256("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJnYXRld2F5IiwiZXhwIjoxNTA5Nzc1OTg4LCJqdGkiOiJhYmNkZTEzNTc4NzIyMjI1OTgiLCJpc3MiOiJmb3NoYW4uY29tIn0", "secret")
	stringsVal := ComputeHmac256("{\"userName\":\"xiaoming\",\"mobile\":\"13887788988\",\"verifyCode\":\"7114\",\"uniqueKey\":\"dddsd789\"}", "secret2")
	fmt.Println(stringsVal) 
}
 
func ComputeHmac256(message string, secret string) string {
    key := []byte(secret)
    h := hmac.New(sha256.New, key)
    h.Write([]byte(message))
	stringsVal := base64.StdEncoding.EncodeToString(h.Sum(nil))
	str := strings.Replace(stringsVal, "=", "", -1)
	str1 := strings.Replace(str, "+", "-", -1)
	str2 := strings.Replace(str1, "/", "_", -1)
	return str2
}

