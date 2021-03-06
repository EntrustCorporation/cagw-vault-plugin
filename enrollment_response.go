/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

type EnrollmentResponse struct {
	Enrollment Enrollment `json:"enrollment"`
	Message    Message    `json:"message"`
}

type Enrollment struct {
	Id     string `json:"id"`
	Status string `json:"status"`
	Body   string `json:"body"`
}
