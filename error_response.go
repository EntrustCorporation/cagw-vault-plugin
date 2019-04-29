/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
)

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

func CheckForError(b *backend, body []byte, statusCode int) error {
	if statusCode != 200 {

		if b.Logger().IsDebug() {
			if statusCode >= 400 {
				b.Logger().Debug(fmt.Sprintf("Received failure response code: %d", statusCode))
			} else {
				b.Logger().Debug(fmt.Sprintf("Received response code: %d", statusCode))
			}
		}

		var errorResponse ErrorResponse
		err := json.Unmarshal(body, &errorResponse)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("CAGW error response could not be parsed (%d)", statusCode))
		}
		return errors.New(fmt.Sprintf("Error from gateway: %s (%d)", errorResponse.Error.Message, statusCode))
	}

	return nil
}
