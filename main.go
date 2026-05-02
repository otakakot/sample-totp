package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/otakakot/sample-totp/internal/key"
)

func main() {
	privKeyA, err := key.GenerateECDH()
	if err != nil {
		panic(err)
	}

	privKeyB, err := key.GenerateECDH()
	if err != nil {
		panic(err)
	}

	commonKeyA, err := privKeyA.ECDH(privKeyB.PublicKey())
	if err != nil {
		panic(err)
	}

	commonKeyB, err := privKeyB.ECDH(privKeyA.PublicKey())
	if err != nil {
		panic(err)
	}

	const period = 10

	otpKeyA, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "example.com",
		AccountName: "alice@example.com",
		Period:      period,
		Secret:      commonKeyA,
	})
	if err != nil {
		panic(err)
	}

	optKeyB, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "example.com",
		AccountName: "alice@example.com",
		Period:      period,
		Secret:      commonKeyB,
	})
	if err != nil {
		panic(err)
	}

	passcode, err := totp.GenerateCode(optKeyB.Secret(), time.Now())
	if err != nil {
		panic(err)
	}

	slog.Info(fmt.Sprintf("Passcode: %s", passcode))

	time.Sleep(60 * time.Second)

	if totp.Validate(passcode, otpKeyA.Secret()) {
		slog.Info("Valid passcode")
	} else {
		slog.Info("Invalid passcode")
	}
}
