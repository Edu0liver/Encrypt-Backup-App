package main

import (
	"fmt"

	"github.com/Edu0liver/Encrypt-Backup-App/internal/server"
)

func main() {

	server := server.NewServer()

	err := server.ListenAndServe()
	if err != nil {
		panic(fmt.Sprintf("cannot start server: %s", err))
	}
}
