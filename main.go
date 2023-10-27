package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// check if a file is a SSH RSA Private key
func isRSAKey(data []byte) bool {
	privateKey := string(data)
	return strings.Contains(privateKey, "PRIVATE KEY") && strings.Contains(privateKey, "SSH")
}

// given a file onject, read information until a nullbyte
// used for the initial null-terminated string
func readUntilNullByte(file *os.File) ([]byte, error) {
	var data []byte
	for {
		var b [1]byte
		_, err := file.Read(b[:])
		if err != nil {
			if err == io.EOF {
				return data, nil
			}
			return nil, err
		}
		if b[0] == 0x00 {
			return data, nil
		}
		data = append(data, b[0])
	}
}

// read the next 4 bytes off of the given file
// used to get length of the next string or byte array
func readLength(file *os.File) int {
	data := makeData(0x4)

	_, err := file.Read(data)
	if err != nil {
		fmt.Println("Error:", err)
		return 0
	}
	length := bytesToInt(data)

	return length
}

// convert a byte array to an integer
func bytesToInt(data []byte) int {
	length := int(binary.BigEndian.Uint32(data))
	return length
}

// convert a byte array to an hex string
func bytesToHex(data []byte) string {
	hexString := hex.EncodeToString(data)
	return hexString
}

// used with the readLength function, reads the specified number
// of bytes from the specified file and returs it as a byte array
func readNumberOfBytes(length int, file *os.File) []byte {
	data := makeData(length)

	_, err := file.Read(data)
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}

	return data
}

// make a data array of a specified length to store
// data read from a file
func makeData(length int) []byte {
	data := make([]byte, length)
	return data
}

// print results of protocol key string
func printProtocolKey(data []byte) {
	fmt.Printf("[~] Protocol Key String: %s\n", string(data))
}

// print results of ciphername and kdfname strings
func printCipherInfo(cipherName, kdfName string) {
	fmt.Printf("[~] Found Cipher Info: %s | %s\n", cipherName, kdfName)
}

// print number of keys found
func printKeyNumber(number int) {
	fmt.Printf("[~] Found %d key\n", number)
}

// print found RSA public exponent `e`
func printExponent(e string, pub bool) {
	if pub {
		fmt.Printf("[~] Found Public Exponent: 0x%s\n", e)
	} else {
		if !fullValuesFlag {
			fmt.Printf("[~] Found Private Exponent: 0x%s...%s\n", e[0:10], e[len(e)-10:])
			return
		}
		fmt.Printf("[~] Found Private Exponent: 0x%s\n", e)
	}
}

// print found RSA modulus `n`
func printModulus(n string, pub bool) {
	if pub {
		if !fullValuesFlag {
			fmt.Printf("[~] Found RSA Modulus: 0x%s...%s\n", n[0:10], n[len(n)-10:])
			return
		}
		fmt.Printf("[~] Found RSA Modulus: 0x%s\n", n)
	} else {
		if !fullValuesFlag {
			fmt.Printf("[~] Found Private RSA Modulus: 0x%s...%s\n", n[0:10], n[len(n)-10:])
			return
		}
		fmt.Printf("[~] Found Private RSA Modulus: 0x%s\n", n)

	}
}

// print found RSA Inverse of Q mod P `iqmp`
func printIQMP(iqmp string) {
	if !fullValuesFlag {
		fmt.Printf("[~] Found Private Exponent: 0x%s...%s\n", iqmp[0:10], iqmp[len(iqmp)-10:])
		return
	}
	fmt.Printf("[~] Found Private Exponent: 0x%s\n", iqmp)
}

// print found RSA primes `p` and `q`
func printPrimes(p, q string) {
	if !fullValuesFlag {
		fmt.Printf("[~] Found RSA Primes 0x%s...%s | 0x%s...%s\n", p[0:10], p[len(p)-10:], q[0:10], q[len(q)-10:])
		return
	}
	fmt.Printf("[~] Found RSA Primes 0x%s | 0x%s\n", p, q)
}

// print key comment at the end of the key
func printComment(comment string) {
	fmt.Printf("[~] Printing comment string: %s\n", comment)
}

var fullValuesFlag bool = false

func main() {
	// check for CLI argument and print help menu
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./sshrecover <id_rsa> [full]")
		return
	}
	filename := os.Args[1]

	// check if the given file is a valid private key
	fileData, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if !isRSAKey(fileData) {
		fmt.Println("[!] The given file is not a valid SSH RSA Private Key... stopping!")
		return
	}

	// check if `full` argument is supplied
	if len(os.Args) == 3 {
		if os.Args[2] == "full" {
			fullValuesFlag = true
		} else {
			fmt.Printf("[!] Unrecognized argument %s, running with default flags\n", os.Args[2])
		}
	} else if len(os.Args) > 3 {
		fmt.Println("Too many arguments. Usage: ./sshrecover <id_rsa> [full]")
		return
	}

	// convert RSA Key to PlainText format
	commandString := fmt.Sprintf("cat %s | grep -v '^--' | base64 -d > %s.pt", filename, filename)
	cmd := exec.Command("bash", "-c", commandString)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		fmt.Println("[!] Error while converting Key to plaintext format:", err)
		return
	}

	newFilename := fmt.Sprintf("%s.pt", filename)

	// check if the given file exists and can be opened
	file, err := os.Open(newFilename)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer file.Close()

	data, err := readUntilNullByte(file)

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// print protocol key result string
	printProtocolKey(data)

	// parse cipher information
	// read next 0x4 bytes for next length
	length := readLength(file)
	// read cipher name
	data = readNumberOfBytes(length, file)
	cipherName := string(data)
	// read next 0x4 bytes for next length
	length = readLength(file)
	// read kdfName
	data = readNumberOfBytes(length, file)
	kdfName := string(data)

	// print resulting cipher info
	printCipherInfo(cipherName, kdfName)

	// parse kdfoptions buffer
	// if the key is not encrypted the size will be 0 and there will be not bytes
	// representing the salt and number of encryption rounds used
	length = readLength(file)
	if length != 0 {
		// TODO: test it agains encrypted key
		fmt.Println("[!] Reading information about salt and rounds")
		data = readNumberOfBytes(length, file)
		fmt.Println(string(data))
	}

	// parse number of keys present
	// this will usually be set to 1
	data = readNumberOfBytes(0x4, file)
	keyNum := bytesToInt(data)
	printKeyNumber(keyNum)

	// parse public key part
	fmt.Println()
	fmt.Println("[*] Parsing Public Key Section [*]")

	readLength(file)
	length = readLength(file)
	readNumberOfBytes(length, file)

	// reading RSA public exponent
	length = readLength(file)
	e := bytesToHex(readNumberOfBytes(length, file))
	printExponent(e, true)

	// reading RSA modulus
	length = readLength(file)
	n := bytesToHex(readNumberOfBytes(length, file))
	printModulus(n, true)

	//parse private key
	fmt.Println()
	fmt.Println("[*] Parsing Private Key Section [*]")

	readLength(file)
	// read 2 check-int values
	checkInt := readNumberOfBytes(0x4, file)
	secondCheckInt := readNumberOfBytes(0x4, file)
	if bytesToHex(checkInt) == bytesToHex(secondCheckInt) {
		fmt.Println("[*] Successfully retrieved two Check-Int values")
	} else {
		fmt.Println("[!] The two found Check-Int values do not match")
		return
	}

	length = readLength(file)
	_ = readNumberOfBytes(length, file)

	// reading private RSA modulus
	length = readLength(file)
	n = bytesToHex(readNumberOfBytes(length, file))
	printModulus(n, false)

	// read public RSA exponent
	length = readLength(file)
	e = bytesToHex(readNumberOfBytes(length, file))
	printExponent(e, true)

	// read private RSA exponent
	length = readLength(file)
	d := bytesToHex(readNumberOfBytes(length, file))
	printExponent(d, false)

	// read RSA IQMP
	length = readLength(file)
	iqmp := readNumberOfBytes(length, file)
	printIQMP(bytesToHex(iqmp))

	// read RSA primes
	length = readLength(file)
	p := bytesToHex(readNumberOfBytes(length, file))
	length = readLength(file)
	q := bytesToHex(readNumberOfBytes(length, file))
	printPrimes(p, q)

	// read key comment string
	length = readLength(file)
	comment := string(readNumberOfBytes(length, file))
	printComment(comment)

	// cleanup section
	fmt.Println()
	fmt.Println("[*] Cleaning up after execution [*]")
	err = os.Remove(newFilename)

	if err != nil {
		return
	}
}
