package main

import "github.com/dgrijalva/jwt-go"
import "github.com/gorilla/context"
import "net/http"
import "strings"
import "time"
import "encoding/json"
import (
	"io/ioutil"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
)

type MyCustomClaims struct {
	HttpBody string `json:"httpBody,omitempty"`
	jwt.StandardClaims
}

type GatewayResponse struct {
	GatewayCode string `json:"gatewayCode"`
	GatewayMsg  string `json:"gatewayMsg"`
}

func setToken(res http.ResponseWriter, req *http.Request) {
	expireToken := time.Now().Add(time.Hour * 24).Unix()
	// expireCookie := time.Now().Add(time.Hour * 24)
	httpBody := "JZZzvh59rKS6q05IPFcmFUTqNYeaf6d5pgiZdRDztSQ"
	claims := MyCustomClaims{ 
		httpBody,
		jwt.StandardClaims{
			ExpiresAt: expireToken,
			Issuer:    "foshan.com",
			Audience:  "gateway",
			Id:        "abcde1357872222598",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, _ := token.SignedString([]byte("secret2"))

	fmt.Printf(signedToken)

	// cookie := http.Cookie{Name: "Auth", Value: signedToken, Expires: expireCookie, HttpOnly: true}
	// http.SetCookie(res, &cookie)

	//测试步骤
	//1.启动gateway
	//2.启动auth 端口 8082
	//3.浏览器：访问：http://172.16.99.31:8082/setToken

	// http.Redirect(res, req, "http://172.16.99.31:8888/user/getImgVerifyCode/1", 301)
	// http.Redirect(res, req, "/profile", 301)


	   client := &http.Client{}
	
	   req, err := http.NewRequest("POST", "http://172.16.99.31:8888/user/getImgVerifyCode/1", strings.NewReader("name=cjb"))
	   if err != nil {
		   // handle error
	   }
	
	   req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	   signedTokens := "Auth=" + signedToken
	   req.Header.Set("Cookie", signedTokens)
	
	   resp, err := client.Do(req)
	
	   defer resp.Body.Close()
	
	   body, err := ioutil.ReadAll(resp.Body)
	   if err != nil {
		   // handle error
	   }
	
	   fmt.Println(string(body))

	   
}

func validate(protectedPage http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {

		cookie, err := req.Cookie("Auth")
		if err != nil {
			http.NotFound(res, req)
			return
		}

		splitCookie := strings.Split(cookie.String(), "Auth=")

		token, err := jwt.ParseWithClaims(splitCookie[1], &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method %v", token.Header["alg"])
			}
			var password string
			password = finduserbyName(token.Claims.(*MyCustomClaims).Issuer)
			fmt.Println(password)
			return []byte(password), nil
		})

		// nonce is exist
		if checkNonce(token.Claims.(*MyCustomClaims).Id) != 1 {
			gatewayResponse := GatewayResponse{
				GatewayCode: "0001",
				GatewayMsg:  "此nonce值已经使用过了",
			}
			jsons, errs := json.Marshal(gatewayResponse)
			if errs != nil {
				fmt.Println(errs.Error())
			}
			fmt.Println(gatewayResponse)
			// fmt.Println(string(b))
			res.Write([]byte(jsons))
			// http.NotFound(res, req)
			return
		}

		if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
			context.Set(req, "Claims", claims)
			// http.NotFound(res, req)
			gatewayResponse := GatewayResponse{
				GatewayCode: "0000",
				GatewayMsg:  "跳转成功",
			}
			jsons, errs := json.Marshal(gatewayResponse)
			if errs != nil {
				fmt.Println(errs.Error())
			}
			fmt.Println(gatewayResponse)
			res.Write([]byte(jsons))
			return

		} else {
			// http.NotFound(res, req)
			gatewayResponse := GatewayResponse{
				GatewayCode: "0002",
				GatewayMsg:  "用户提供密码有误",
			}
			jsons, errs := json.Marshal(gatewayResponse)
			if errs != nil {
				fmt.Println(errs.Error())
			}
			fmt.Println(gatewayResponse)
			res.Write([]byte(jsons))

			return
		}
		protectedPage(res, req)
	})
}

func profile(res http.ResponseWriter, req *http.Request) {
	fmt.Print("xxxxxxxxxxx")
	claims := context.Get(req, "Claims").(*MyCustomClaims)
	fmt.Println(claims.StandardClaims)
	res.Write([]byte(claims.StandardClaims.Issuer))
	context.Clear(req)
}

func homePage(res http.ResponseWriter, req *http.Request) {
	res.Write([]byte("Home Page123"))
}

//check nonce does it exist ；default 1（not exist nonce,execute insert);  2:exist 3: error
func checkNonce(gatewayNonce string) (nonceStatus int) {
	db, err := sql.Open("mysql", "root:pass123word01@tcp(172.16.192.91:3308)/gateway?charset=utf8")
	nonceStatus = 1 //default 1 is not exist
	if err != nil {
		fmt.Println(err)
		nonceStatus = 3
		return nonceStatus
	}

	defer db.Close()

	var rows *sql.Rows
	rows, err = db.Query("select * from gateway_nonce")
	if err != nil {
		fmt.Println(err)
		nonceStatus = 3
		return nonceStatus
	}

	for rows.Next() {
		var nonce string
		var id int
		rows.Scan(&id, &nonce)
		fmt.Println(id, "\t", nonce)
		//if nonce hava been black dont insert table
		if strings.EqualFold(nonce, gatewayNonce) {
			nonceStatus = 2 // status 2 is exist
			break
		}
	}

	if nonceStatus == 1 {
		var result sql.Result
		result, err = db.Exec("insert into gateway_nonce(nonce) values(?)", gatewayNonce)
		if err != nil {
			fmt.Println(err)
			nonceStatus = 3
			return nonceStatus
		}
		lastId, _ := result.LastInsertId()
		fmt.Println("insert record's id:", lastId)

	} else {
		fmt.Println("this record is exist!!!")
	}
	rows.Close()
	return nonceStatus
}

//find user information
func finduserbyName(name string) (password string) {
	db, err := sql.Open("mysql", "root:pass123word01@tcp(172.16.192.91:3308)/gateway?charset=utf8")
	password = ""
	if err != nil {
		fmt.Println(err)
		return password
	}

	defer db.Close()

	var rows *sql.Rows
	fmt.Println(name)
	rows, err = db.Query("select * from gateway_user where username = ?", name)
	if err != nil {
		fmt.Println(err)
		return password
	}
	for rows.Next() {
		var username string
		var id int
		var userpassword string
		var createtime string
		var updatetime string
		var status int
		rows.Scan(&id, &username, &userpassword, &createtime, &updatetime, &status)
		fmt.Println(id, "\t", username, "\t", userpassword)
		if !strings.EqualFold(userpassword, "") {
			password = userpassword
		}
	}
	return password
}

func main() {
	http.HandleFunc("/profile", validate(profile))
	http.HandleFunc("/setToken", setToken)
	http.HandleFunc("/", homePage)
	http.ListenAndServe(":8082", nil)
}
