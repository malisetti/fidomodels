package errors

import (
	messages "github.com/mseshachalam/fidomodels/models"
	"strconv"
)

type AppError struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Details string `json:"details"`
}

type UAFError struct {
	Status  int         `json:"statusCode"`
	Message string      `json:"description"`
	Details interface{} `json:"details"`
}

var StatusCodes = map[int]UAFError{
	messages.OPERATION_COMPLETED:              {Status: 1200, Message: "OK.", Details: "Operation completed."},
	messages.MESSAGE_ACCEPTED:                 {Status: 1202, Message: "Accepted.", Details: "Message accepted, but not completed at this time. The RP may need time to process the attestation, run risk scoring, etc. The server should not send an authenticationToken with a 1202 response."},
	messages.BAD_REQUEST:                      {Status: 1400, Message: "Bad Request.", Details: "The server did not understand the message."},
	messages.UNAUTHORIZED:                     {Status: 1401, Message: "Unauthorized.", Details: "The userid must be authenticated to perform this operation, or this KeyID is not associated with this UserID."},
	messages.FORBIDDEN:                        {Status: 1403, Message: "Forbidden.", Details: "The userid is not allowed to perform this operation. Client should not retry."},
	messages.NOT_FOUND:                        {Status: 1404, Message: "Not Found.", Details: ""},
	messages.REQUEST_TIMEOUT:                  {Status: 1408, Message: "Request Timeout.", Details: ""},
	messages.UNKOWN_AAID:                      {Status: 1480, Message: "Unknown AAID.", Details: "The server was unable to locate authoritative metadata for the AAID."},
	messages.UNKOWN_KEYID:                     {Status: 1481, Message: "Unknown KeyID.", Details: "The server was unable to locate a registration for the given UserID and KeyID combination. This error indicates that there is an invalid registration on the user's device. It is recommended that FIDO UAF Client deletes the key from local device when this error is received."},
	messages.CHANNEL_BINDING_REFUSED:          {Status: 1490, Message: "Channel Binding Refused.", Details: "The server refused to service the request due to a missing or mismatched channel binding(s)."},
	messages.INVALID_REQUEST:                  {Status: 1491, Message: "Request Invalid.", Details: "The server refused to service the request because the request message nonce was unknown, expired or the server has previously serviced a message with the same nonce and user ID."},
	messages.UNACCEPTABLE_AUTHENTICATOR:       {Status: 1492, Message: "Unacceptable Authenticator.", Details: "The authenticator is not acceptable according to the server's policy, for example, because the capability registry used by the server reported different capabilities than client-side discovery."},
	messages.REVOKED_AUTHENTICATOR:            {Status: 1493, Message: "Revoked Authenticator.", Details: "The authenticator is considered revoked by the server."},
	messages.UNACCEPTABLE_KEY:                 {Status: 1494, Message: "Unacceptable Key.", Details: "The key used is unacceptable. Perhaps it is on a list of known weak keys or uses insecure parameter choices."},
	messages.UNACCEPTABLE_ALGORITHM:           {Status: 1495, Message: "Unacceptable Algorithm.", Details: "The server believes the authenticator to be capable of using a stronger mutually-agreeable algorithm than was presented in the request."},
	messages.UNACCEPTABLE_ATTESTATION:         {Status: 1496, Message: "Unacceptable Attestation.", Details: "The attestation(s) provided were not accepted by the server."},
	messages.UNACCEPTABLE_CLIENT_CAPABILITIES: {Status: 1497, Message: "Unacceptable Client Capabilities.", Details: "The server was unable or unwilling to use required capabilities provided supplementally to the authenticator by the client software."},
	messages.UNACCEPTABLE_CONTENT:             {Status: 1498, Message: "Unacceptable Content.", Details: "There was a problem with the contents of the message and the server was unwilling or unable to process it."},
	messages.INTERNAL_SERVER_ERROR:            {Status: 1500, Message: "Internal Server Error", Details: ""},
}

func NewAppError(message string, status int, details string) *AppError {
	t := AppError{}
	t.Status = status
	t.Message = message
	t.Details = details

	return &t
}

func (e *AppError) Error() string {
	return "Status : " + strconv.Itoa(e.Status) + "Message : " + e.Message
}

func NewUAFError(message string, status int, details interface{}) *UAFError {
	t := UAFError{}
	t.Status = status
	t.Message = message
	t.Details = details

	return &t
}

func (e *UAFError) Error() string {
	return "Status : " + strconv.Itoa(e.Status) + "Message : " + e.Message
}
