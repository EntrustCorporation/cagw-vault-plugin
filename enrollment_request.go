package main

type EnrollmentRequest struct {
	profileId string
	requiredFormat RequiredFormat
	csr string
}

type RequiredFormat struct {
	format string
}