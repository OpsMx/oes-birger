package fwdapi

import (
	"log"
	"regexp"
)

// NamePresent ensures the string is not null.
func NamePresent(n string) bool {
	return n != ""
}

// TypeValid ensures type is valid, that is, lowercase alpha only
func TypeValid(n string) bool {
	matched, err := regexp.MatchString("^[a-z]+$", n)
	if err != nil {
		// TODO: handle this better
		log.Printf("matching service type: %v", err)
		return false
	}
	return matched
}
