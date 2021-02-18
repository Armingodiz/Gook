package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/ArminGodiz/Gook/utils/rest_errors"
	"github.com/go-resty/resty/v2"
	"net/http"
	"strconv"
	"strings"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = resty.New()
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) *rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Code == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *rest_errors.RestErr) {
	response, err := oauthRestClient.R().
		EnableTrace().
		Get(fmt.Sprintf("http://localhost:2222/oauth/access_token/%s", accessTokenId))
	if err != nil {
		return nil, rest_errors.NewInternalServerError("error while sending get request : " + err.Error())
	}
	if response == nil || response.RawResponse == nil {
		return nil, rest_errors.NewInternalServerError("invalid restclient response when trying to get access token" +
			"network timeout")
	}

	if response.StatusCode() > 299 {
		var restErr rest_errors.RestErr
		err := json.Unmarshal(response.Body(), &restErr)
		fmt.Println(response.String())
		if err != nil { // we get a different type of error
			return nil, rest_errors.NewInternalServerError("Unknown error type accrued while trying to login ==>" + err.Error())
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Body(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal access token response  : " + "error processing json")
	}
	return &at, nil
}
