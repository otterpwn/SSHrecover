## Overview
`SSHrecover` is a Proof of Concept project based on [this](https://www.youtube.com/watch?v=4F1XGsvB2iA) video by [IppSec](https://github.com/IppSec) that shows how it's possible to recover RSA private and public varibles from a total or partial SSH key.

## Usage
The project it's written in GoLang and does not require any non-default packages/dependencies.
The script can be ran without compiling with
```
go run main.go <filename> (priv / pub) [full]
```
to compile the script you can run
```
go build
```
in the project directory.

- Parsing private key
```
./sshrecover id_rsa priv
# or to print the full parameter values
./sshrecover id_rsa priv full
```
- Parsing public key
```
./sshrecover id_rsa.pub pub
# or to print the full parameter values
./sshrecover id_rsa.pub pub full
```

## TODO
- [x] Add functionality to parse encrypted keys
- [ ] Better output handling for john command (used when user chooses to crack password of an encrypted key)
