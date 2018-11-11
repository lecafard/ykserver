package main

import (
	"bytes"
	"crypto/aes"
	"database/sql"
	"encoding/binary"
	"errors"
	"github.com/snksoft/crc"
)

const MODHEX = "cbdefghijklnrtuv"

func FromModHex(data string) ([]byte, error) {
	length := len(data)
	if length%2 != 0 {
		return nil, errors.New("InvalidModHexLength")
	}
	arr := make([]byte, length/2)

	n := byte(0)
	for i := 0; i < length; i++ {
		f := 0
		for j := 0; j < 16; j++ {
			if MODHEX[j] == data[i] {
				f = 1
				if i%2 == 0 {
					n = byte(j * 16)
				} else {
					n += byte(j)
				}
				break
			}
		}

		if f == 0 {
			return nil, errors.New("InvalidModHex")
		}

		if i%2 == 1 && i != 0 {
			arr[i/2] = n
		}
	}
	return arr, nil
}

func DecryptCTR(key []byte, priv []byte, payload []byte) (int, []byte, error) {
	dec := make([]byte, 16)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return -1, nil, errors.New("AESError")
	}

	cipher.Decrypt(dec, payload)
	ctr := int(binary.LittleEndian.Uint16(dec[6:8]))
	crcreq := uint64(binary.LittleEndian.Uint16(dec[14:16]))
	nonce := dec[12:14]
	privc := dec[0:6]

	if bytes.Compare(privc, priv) != 0 {
		return -1, nil, errors.New("InvalidPrivID")
	}

	crccalc := crc.CalculateCRC(crc.X25, dec[0:14])
	if crcreq != crccalc {
		return -1, nil, errors.New("InvalidCRC")
	}

	return ctr, nonce, nil
}

func VerifyOTP(otp string) (string, int, []byte, error) {
	if len(otp) != 44 {
		return "", -1, nil, errors.New("InvalidOTP")
	}

	// extract the first 12 characters (this is the id)
	tidS := otp[0:12]
	pwd := otp[12:44]

	// just checking
	tid, err := FromModHex(tidS)
	if err != nil {
		return "", -1, nil, errors.New("InvalidOTP")
	}

	payload, err := FromModHex(pwd)
	if err != nil {
		return "", -1, nil, err
	}

	row := db.QueryRow("SELECT pid,key FROM otp_tokens WHERE tid=?", tid)
	var pid, key []byte

	err = row.Scan(&pid, &key)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", -1, nil, errors.New("InvalidToken")
		} else {
			return "", -1, nil, errors.New("DBError")
		}
	}

	// decrypt token and get counter
	ctr, nonce, err := DecryptCTR(key, pid, payload)

	if err != nil {
		return "", -1, nil, errors.New("InvalidOTP")
	}

	// now query ctr
	row = db.QueryRow(
		"SELECT 1 from otp_logs WHERE tid=? AND (ctr>? OR (ctr=? AND nonce=?))",
		tid, ctr, ctr, nonce,
	)
	var disp int
	err = row.Scan(&disp)
	if err != nil && err != sql.ErrNoRows {
		return "", -1, nil, errors.New("DBError")
	} else if err == nil {
		return tidS, ctr, nonce, errors.New("ReplayedOTP")
	}

	// log to db
	stmt, _ := db.Prepare("INSERT INTO otp_logs (tid, nonce, ctr) VALUES(?, ?, ?)")
	stmt.Exec(tid, nonce, ctr)

	return tidS, ctr, nonce, nil
}
