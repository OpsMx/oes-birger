package fwdapi

type HttpErrorMessage struct {
	Message string `json:"message"`
}

type HttpErrorResponse struct {
	Error *HttpErrorMessage `json:"error"`
}
