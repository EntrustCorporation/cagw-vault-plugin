package main

type ErrorResponse struct {
	message Message
	error Error
}

type Error struct {
	code string
	message string
	target string
	value string
}