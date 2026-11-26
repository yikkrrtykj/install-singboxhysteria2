package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/windowsobs"
)

func main() {
	profilePath := flag.String("profile", "", "path to the local observation profile JSON")
	secretPath := flag.String("secret-file", "", "path to the local Mihomo controller secret")
	flag.Parse()
	if *profilePath == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*profilePath, *secretPath, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(profilePath, secretPath string, output io.Writer) error {
	raw, err := readBounded(profilePath, 16384)
	if err != nil {
		return errors.New("cannot read the observation profile")
	}
	var profile windowsobs.Profile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return errors.New("invalid observation profile JSON")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("invalid observation profile JSON")
	}

	var secret string
	if secretPath != "" {
		raw, err := readBounded(secretPath, 4096)
		if err != nil {
			return errors.New("cannot read the controller secret")
		}
		secret = strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
		if secret == "" {
			return errors.New("empty controller secret")
		}
	}

	observer, err := windowsobs.New(profile, secret)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	if err := json.NewEncoder(output).Encode(observer.Collect(ctx)); err != nil {
		return errors.New("cannot write the observation")
	}
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("expected a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("file is larger than the configured limit")
	}
	return raw, nil
}
