package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

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
func printPubExponent(e string) {
	fmt.Printf("[~] Found Public Exponent: 0x%s\n", e)
}

// print found RSA modulus `n`
func printModulus(n string) {
	if !fullValuesFlag {
		fmt.Printf("[~] Found RSA Modulus: 0x%s...%s\n", n[0:10], n[len(n)-10:])
		return
	}
	fmt.Printf("[~] Found RSA Modulus: 0x%s\n", n)

}

var fullValuesFlag bool = false

func main() {
	// check for CLI argument and print help menu
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./sshrecover <filename> [full]")
		return
	}
	filename := os.Args[1]

	// check if `full` argument is supplied
	if len(os.Args) == 3 {
		if os.Args[2] == "full" {
			fullValuesFlag = true
		} else {
			fmt.Printf("[!] Unrecognized argument %s, running with default flags\n", os.Args[2])
		}
	} else if len(os.Args) > 3 {
		fmt.Println("Too many arguments. Usage: ./sshrecover <filename> [full]")
		return
	}

	// check if the given file exists and can be opened
	file, err := os.Open(filename)
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
	printPubExponent(e)

	// reading RSA modulus
	length = readLength(file)
	n := bytesToHex(readNumberOfBytes(length, file))
	printModulus(n)

	//parse private key
}
