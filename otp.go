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

func DecryptCTR(key []byte, priv []byte, payload []byte) (int, error) {
	dec := make([]byte, 16)
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return -1, errors.New("AESError")
	}

	cipher.Decrypt(dec, payload)
	ctr := int(binary.LittleEndian.Uint16(dec[6:8]))
	crcreq := uint64(binary.LittleEndian.Uint16(dec[14:16]))
	privc := dec[0:6]

	if bytes.Compare(privc, priv) != 0 {
		return -1, errors.New("InvalidPrivID")
	}

	crccalc := crc.CalculateCRC(crc.X25, dec[0:14])
	if crcreq != crccalc {
		return -1, errors.New("InvalidCRC")
	}

	return ctr, nil
}

func VerifyOTP(otp string) (string, int, error) {
	if len(otp) != 44 {
		return "", -1, errors.New("InvalidOTP")
	}

	// extract the first 12 characters (this is the id)
	tid := otp[0:12]
	pwd := otp[12:44]

	// just checking
	_, err := FromModHex(tid)
	if err != nil {
		return "", -1, errors.New("InvalidOTP")
	}

	payload, err := FromModHex(pwd)
	if err != nil {
		return "", -1, err
	}

	row := db.QueryRow("SELECT ctr,pid,key FROM otp_tokens WHERE tid=?", tid)
	var ctr int
	var pid, key []byte

	err = row.Scan(&ctr, &pid, &key)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", -1, errors.New("InvalidToken")
		} else {
			return "", -1, errors.New("DBError")
		}
	}

	// decrypt token and get counter
	newCtr, err := DecryptCTR(key, pid, payload)

	if err != nil {
		return "", -1, errors.New("InvalidOTP")
	}

	if newCtr < ctr {
		return tid, newCtr, errors.New("ReplayedOTP")
	}

	// log to db
	stmt, _ := db.Prepare("INSERT INTO otp_logs (tid, ctr) VALUES(?, ?)")
	stmt.Exec(tid, newCtr)
	stmt, _ = db.Prepare("UPDATE otp_tokens SET ctr=? WHERE tid=?")
	stmt.Exec(newCtr, tid)

	return tid, newCtr, nil
}
