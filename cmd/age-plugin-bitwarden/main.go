package main

import (
	"log"

	"github.com/Enzyme/age-plugin-pwmanager/internal/pwmanager"
)

func main() {

	var example = `
  $ age-plugin-bitwarden --print-recipients
  op://Personal/SSH key/public key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINKZfejb9htpSB5K9p0RuEowErkba2BMKaze93ZVkQIE

  $ echo "Hello World" | age -r "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINKZfejb9htpSB5K9p0RuEowErkba2BMKaze93ZVkQIE" > secret.age

  $ age --decrypt -j bitwarden -o - secret.age
  Hello World`

	log.Println("Using Bitwarden as backend")
	backend := Bitwarden{}
	rootCmd := pwmanager.RootCmd(backend, example)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}

}
