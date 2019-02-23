package main

type EnrollmentRequest struct {
	ProfileId        string            `json:"profileId"`
	RequiredFormat   RequiredFormat    `json:"requiredFormat"`
	CSR              string            `json:"csr"`
	SubjectVariables []SubjectVariable `json:"subjectVariables"`
}

type RequiredFormat struct {
	Format string `json:"format"`
}

type SubjectVariable struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
