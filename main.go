package main

import (
	"database/sql"
	"github.com/julienschmidt/httprouter"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
)

var db *sql.DB

func main() {
	var err error

	// open database
	db, err = sql.Open("sqlite3", "./data.db")
	if err != nil {
		panic(err)
	}

	router := httprouter.New()

	router.POST("/verify", PostVerify)
	router.GET("/admin", GetAdmin)
	router.GET("/admin/users/create", PostAdminCreateUser)
	router.GET("/admin/users/modify", PostAdminModifyUser)
	router.POST("/admin/tokens/create", PostAdminCreateToken)
	router.POST("/admin/tokens/delete", PostAdminDeleteToken)
	router.POST("/admin/login", PostAdminLogin)
	router.GET("/admin/logout", GetAdminLogout)

	log.Fatal(http.ListenAndServe(":3000", router))
}
