package main

type ErrorResponse struct {
	Message Message `json:"message"`
	Error   Error   `json:"error"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Target  string `json:"target"`
	Value   string `json:"value"`
}
