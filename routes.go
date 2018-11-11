package main

import (
	"fmt"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func GetAdmin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// check auth status
}

func PostAdminCreateUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// check auth status
}

func PostAdminModifyUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// check auth status
}

func PostAdminCreateToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// check auth status
}

func PostAdminDeleteToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// check auth status
}

func PostAdminLogin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
}

func GetAdminLogout(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
}

func PostVerify(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("content-type", "application/json")

	r.ParseForm()
	otp := r.Form.Get("otp")

	tid, ctr, nonce, err := VerifyOTP(otp)

	if err != nil {
		if tid != "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w,
				"{\"error\":\"%s\",\"status\":false,\"tid\":\"%s\",\"ctr\":%d,\"nonce\":\"%x\"}",
				err.Error(), tid, ctr, nonce)
			return
		} else {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w,
		"{\"status\":true,\"tid\":\"%s\",\"ctr\":%d,\"nonce\":\"%x\"}",
		tid, ctr, nonce)

	/*
		if len(otp) != 44 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("{\"error\":\"InvalidOTP\"}"))
			return
		}

		// extract the first 12 characters (this is the id)
		tid := otp[0:12]
		pwd := otp[12:44]

		// just checking
		_, err := FromModHex(tid)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("{\"error\":\"" + err.Error() + "\"}"))
			return
		}

		payload, err := FromModHex(pwd)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("{\"error\":\"" + err.Error() + "\"}"))
			return
		}

		row := db.QueryRow("SELECT ctr,pid,key FROM otp_tokens WHERE tid=?", tid)
		var ctr int
		var pid, key []byte

		err = row.Scan(&ctr, &pid, &key)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			if err == sql.ErrNoRows {
				w.Write([]byte("{\"error\":\"InvalidToken\"}"))
			} else {
				w.Write([]byte("{\"error\":\"DBError\"}"))
			}
			return
		}

		// decrypt token and get counter
		newCtr, err := DecryptCTR(key, pid, payload)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("{\"error\":\"InvalidOTP\"}"))
			return
		}

		if newCtr < ctr {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w,
				"{\"error\":\"ReplayedOTP\",\"status\":false,\"tid\":\"%s\",\"ctr\":%d}",
				tid, newCtr,
			)
			return
		}

		// log to db
		stmt, _ := db.Prepare("INSERT INTO otp_logs (tid, ctr) VALUES(?, ?)")
		stmt.Exec(tid, newCtr)
		stmt, _ = db.Prepare("UPDATE otp_tokens SET ctr=? WHERE tid=?")
		stmt.Exec(newCtr, tid)

		fmt.Fprintf(w, "{\"status\":true,\"tid\":\"%s\",\"ctr\":%d}", tid, newCtr)
	*/
}
