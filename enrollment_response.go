package main

type EnrollmentResponse struct {
	enrollment Enrollment
	message Message
}

type Enrollment struct {
	id string
	status string
	body []byte
}