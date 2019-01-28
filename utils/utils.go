package utils

import (
	"bufio"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/furiousk/go.models/models"
	"golang.org/x/crypto/bcrypt"
)

const (
	geocon = 360000
)

//ReadOptions ...
func ReadOptions(file string) (config *models.Environment) {

	_file, err := os.Open(file)
	Check(err)
	defer _file.Close()

	scanner := bufio.NewScanner(_file)
	_map := make(map[string]string)

	for scanner.Scan() {
		newarray := strings.Split(scanner.Text(), "=")
		_map[newarray[0]] = newarray[1]
	}

	config = &models.Environment{
		Appname:      _map["APP_NAME"],
		Appenv:       _map["APP_ENV"],
		Appport:      _map["APP_PORT"],
		Dbconnection: _map["DB_CONNECTION"],
		Dbhost:       _map["DB_HOST"],
		Dbport:       _map["DB_PORT"],
		Dbdatabase:   _map["DB_DATABASE"],
		Dbusername:   _map["DB_USERNAME"],
		Dbpassword:   _map["DB_PASSWORD"],
		Exturl:       _map["EXT_URL"],
		Exttoken:     _map["EXT_TOKEN"],
		Extdias:      _map["EXT_DIAS"],
	}

	if serr := scanner.Err(); serr != nil {
		log.Fatal(serr)
	}

	return
}

//CoordinatesAdjusts ....
func CoordinatesAdjusts(lat string, lng string, decimalPlaces int) (_q [2]float64) {

	pow := math.Pow(10, float64(decimalPlaces))

	clat, _ := strconv.ParseFloat(lat, 64)
	clng, _ := strconv.ParseFloat(lng, 64)

	log.Println(clat, clng)

	_lat := math.Ceil(clat*pow) / pow
	_lng := math.Ceil(clng*pow) / pow

	log.Println(_lat, _lng)

	_q = [2]float64{
		_lng,
		_lat,
	}
	return
}

//HashPassword ....
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

//CheckPasswordHash ....
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//SetInterval ...
func SetInterval(someFunc func(), milliseconds uint64, async bool) chan bool {

	interval := time.Duration(milliseconds) * time.Millisecond
	ticker := time.NewTicker(interval)
	clear := make(chan bool)

	go func() {
		for {
			select {
			case <-ticker.C:
				if async {
					go someFunc()
				} else {
					someFunc()
				}
			case <-clear:
				ticker.Stop()
				return
			}
		}
	}()
	return clear
}

//Substr ...
func Substr(str string, from int, to int) string {

	var newstring string
	count := from + to
	for i := 0; i < len(str); i++ {
		if i >= from && i < count {
			newstring += string(str[i])
		}
	}
	log.Println(newstring)
	return newstring
}

//Invertbin ...
func Invertbin(str string) string {

	var newbin string
	for i := range str {
		switch {
		case string(str[i]) == "0":
			newbin += "1"
		case string(str[i]) == "1":
			newbin += "0"
		}
	}
	return newbin
}

//Sumbin ...
func Sumbin(str string) string {

	len := len(str) - 1
	newarray := strings.Split(str, "")

	for i := 0; i <= len; len-- {

		if string(newarray[len]) == "0" {

			newarray[len] = "1"
			//return strings.Join(newarray, "")

		} else {

			newarray[len] = "0"
		}
	}
	return strings.Join(newarray, "")
}

//Pad ....
func Pad(str string, side string, size int) (newstr string) {

	newstr = str
	for len(newstr) < size {
		switch {
		case side == "L":
			newstr = "0" + newstr
		case side == "R":
			newstr = newstr + "0"
		}
	}
	return
}

//Makepos ....
func Makepos(pos string) (lat, lng float64) {

	latstr := Substr(pos, 0, 8)
	lngstr := Substr(pos, 8, 8)

	_lat := TrimLeftChar(latstr, "0")
	_lng := TrimLeftChar(lngstr, "0")

	_latdec := Hex2dec(_lat)
	_lngdec := Hex2dec(_lng)

	_latbin := Dec2bin(_latdec)
	_lngbin := Dec2bin(_lngdec)

	lat = Show27bin(_latbin)
	lng = Show27bin(_lngbin)

	return
}

//Show27bin ...
func Show27bin(str string) float64 {

	data := strings.Split(str, "")
	key := len(data) - 27
	var _dec int

	if data[key] == "1" {

		_bin := Invertbin(str)
		_bin2 := Sumbin(_bin)
		_dec = Bin2dec(_bin2)

	} else {

		_dec = Bin2dec(str)
	}
	return ((float64(_dec) / geocon) * -1)
}

//Ternary ....
func Ternary(vlra string, vlrb string, retorno string) (result string) {
	result = "0"
	if vlra == vlrb {
		result = retorno
	}
	return
}

//CheckOneByte ....
func CheckOneByte(size int, hex string, key string, m map[string]map[string]models.Mult) int {

	ibyte := Substr(hex, size, 2)
	i := Pad(Hex2bin(ibyte), "L", 8)
	split := strings.Split(i, "")
	_, ok := m[key]

	if !ok {
		m[key] = make(map[string]models.Mult)
	}

	switch key {
	case "0":
		m[key]["0"] = models.Mult{Name: "systimestamp", Len: Ternary(split[7], "1", "8")}
		m[key]["1"] = models.Mult{Name: "positioning", Len: Ternary(split[6], "1", "16")}
		m[key]["2"] = models.Mult{Name: "gprssinalqly", Len: Ternary(split[5], "1", "2")}
		m[key]["3"] = models.Mult{Name: "gpstimestamp", Len: Ternary(split[4], "1", "8")}
		m[key]["4"] = models.Mult{Name: "gpscourse", Len: Ternary(split[3], "1", "4")}
		m[key]["5"] = models.Mult{Name: "gpsinstspeed", Len: Ternary(split[2], "1", "4")}
		m[key]["6"] = models.Mult{Name: "gpsdigstatus", Len: Ternary(split[1], "1", "2")}
		break

	case "1":
		m[key]["0"] = models.Mult{Name: "gpssatellite", Len: Ternary(split[7], "1", "2")}
		m[key]["1"] = models.Mult{Name: "gpsdop", Len: Ternary(split[6], "1", "2")}
		m[key]["2"] = models.Mult{Name: "inputstatus", Len: Ternary(split[5], "1", "4")}
		m[key]["3"] = models.Mult{Name: "extinputstt", Len: Ternary(split[4], "1", "4")}
		m[key]["4"] = models.Mult{Name: "extinputst2", Len: Ternary(split[3], "1", "4")}
		m[key]["5"] = models.Mult{Name: "outputstatus", Len: Ternary(split[2], "1", "4")}
		m[key]["6"] = models.Mult{Name: "batteryvolts", Len: Ternary(split[1], "1", "4")}
		break

	case "2":
		m[key]["0"] = models.Mult{Name: "backupbattvol", Len: Ternary(split[7], "1", "4")}
		m[key]["1"] = models.Mult{Name: "temperature", Len: Ternary(split[6], "1", "2")}
		m[key]["2"] = models.Mult{Name: "backofficelk", Len: Ternary(split[5], "1", "2")}
		m[key]["3"] = models.Mult{Name: "odometer", Len: Ternary(split[4], "1", "8")}
		m[key]["4"] = models.Mult{Name: "sai", Len: Ternary(split[3], "1", "var")}
		m[key]["5"] = models.Mult{Name: "accelerometerx", Len: Ternary(split[2], "1", "4")}
		m[key]["6"] = models.Mult{Name: "accelerometery", Len: Ternary(split[2], "1", "4")}
		m[key]["6"] = models.Mult{Name: "accelerometerz", Len: Ternary(split[2], "1", "4")}
		m[key]["6"] = models.Mult{Name: "accelerometerr", Len: Ternary(split[2], "1", "4")}
		m[key]["6"] = models.Mult{Name: "vehiclespeed", Len: Ternary(split[1], "1", "4")}

	case "3":
		m[key]["0"] = models.Mult{Name: "enginespeed", Len: Ternary(split[7], "1", "4")}
		m[key]["1"] = models.Mult{Name: "canstatus", Len: Ternary(split[6], "1", "2")}
		m[key]["2"] = models.Mult{Name: "vehicspeedcan", Len: Ternary(split[5], "1", "2")}
		m[key]["3"] = models.Mult{Name: "odometercan", Len: Ternary(split[4], "1", "8")}
		m[key]["4"] = models.Mult{Name: "engispeedcan", Len: Ternary(split[3], "1", "4")}
		m[key]["5"] = models.Mult{Name: "temperaturecan", Len: Ternary(split[2], "1", "4")}
		m[key]["6"] = models.Mult{Name: "fuelconsumcan", Len: Ternary(split[1], "1", "8")}
		break

	case "4":
		m[key]["0"] = models.Mult{Name: "transmissiongear", Len: Ternary(split[7], "1", "2")}
		m[key]["1"] = models.Mult{Name: "averagespeed", Len: Ternary(split[6], "1", "4")}
		m[key]["2"] = models.Mult{Name: "engiruntimemet", Len: Ternary(split[5], "1", "8")}
		m[key]["3"] = models.Mult{Name: "fencegroupaid", Len: Ternary(split[4], "1", "4")}
		m[key]["4"] = models.Mult{Name: "fencegroupbid", Len: Ternary(split[3], "1", "4")}
		m[key]["5"] = models.Mult{Name: "fencerouteid", Len: Ternary(split[2], "1", "4")}
		m[key]["6"] = models.Mult{Name: "odometersensor", Len: Ternary(split[1], "1", "8")}
		break

	case "5":
		m[key]["0"] = models.Mult{Name: "driverident", Len: Ternary(split[7], "1", "var")}
		m[key]["1"] = models.Mult{Name: "timestampevdisc", Len: Ternary(split[6], "1", "2")}
		m[key]["2"] = models.Mult{Name: "bvdrstatus", Len: Ternary(split[5], "1", "2")}
		m[key]["3"] = models.Mult{Name: "bvdrserialnun", Len: Ternary(split[4], "1", "16")}
		m[key]["4"] = models.Mult{Name: "odometergpsmet", Len: Ternary(split[3], "1", "8")}
		m[key]["5"] = models.Mult{Name: "engineruntimecan", Len: Ternary(split[2], "1", "8")}
		m[key]["6"] = models.Mult{Name: "reservad", Len: Ternary(split[1], "1", "0")}
		break

	}
	if split[0] == "1" {

		size += 2
		_key, _ := strconv.Atoi(string(key))
		_key++
		_keystr := strconv.Itoa(_key)
		size = CheckOneByte(size, hex, _keystr, m)
	}
	return size
}

//Bin2dec ...
func Bin2dec(hexStr string) int { // testado
	// base 2 for binary
	result, _ := strconv.ParseInt(hexStr, 2, 64)
	return int(result)
}

//Bin2hex ...
func Bin2hex(binStr string) string { // testado
	// base 2 for binary
	dec := Bin2dec(binStr)
	hex := Dec2hex(dec)
	return string(hex)
}

//Dec2bin ...
func Dec2bin(dec int) string { // testado
	// base 10 for decimal
	result := strconv.FormatInt(int64(dec), 2)
	return string(result)
}

//Dec2hex ...
func Dec2hex(dec int) string { // testado
	// base 10 for decimal
	result := strconv.FormatInt(int64(dec), 16)
	return string(result)
}

//Hex2bin ...
func Hex2bin(hexStr string) string { // testado
	// base 16 for hexadecimal
	dec := Hex2dec(hexStr)
	bin := Dec2bin(dec)
	return string(bin)
}

//Hex2dec ...
func Hex2dec(hexStr string) int { // testado
	// base 16 for hexadecimal
	result, _ := strconv.ParseInt(hexStr, 16, 64)
	return int(result)
}

//TrimLeftChar ....
func TrimLeftChar(s string, ocor string) string {
	if s[0:1] == ocor {
		return s[1:]
	}
	return s[:0]
}

//Check ...
func Check(err error) {
	if err != nil {
		panic(err)
	}
}

//DiffDate ...
func DiffDate(date time.Time) (_hrs int) {

	_now := time.Now()
	_sub := _now.Add(-10 * time.Hour)
	_dif := _sub.Sub(date)
	_hrs = int(_dif.Hours())

	return
}
