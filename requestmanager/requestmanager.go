package requestmanager

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/valyala/fasthttp"
)

var DEBUG = true

type RequestManager struct {
	Method     string
	Url        string
	Payload    interface{}
	req        *fasthttp.Request
	httpClient *fasthttp.Client
}

func New(method, url string, payload interface{}, httpClient *fasthttp.Client) *RequestManager {
	r := &RequestManager{
		Method:  method,
		Url:     url,
		Payload: payload,
	}

	if httpClient != nil {
		r.httpClient = httpClient
	} else {
		r.httpClient = new(fasthttp.Client)
	}

	r.req = fasthttp.AcquireRequest()
	r.req.Header.SetContentType("application/json")
	r.req.Header.SetMethod(method)
	r.req.SetRequestURIBytes([]byte(url))

	if r.Method == fasthttp.MethodPost ||
		r.Method == fasthttp.MethodPut ||
		r.Method == fasthttp.MethodPatch &&
			r.Payload != nil {

		payloadJsonString, err := json.Marshal(r.Payload)
		if err != nil {
			fmt.Println(err)
			return nil
		}

		r.req.SetBody(payloadJsonString)
	}

	return r
}

func (r *RequestManager) SetAuthToken(token string) *RequestManager {
	r.req.Header.Set("Authorization", token)
	return r
}

func (r *RequestManager) SetHttpClient(httpClient *fasthttp.Client) *RequestManager {
	r.httpClient = httpClient
	return r
}

func (r *RequestManager) SetRequest(request *fasthttp.Request) *RequestManager {
	r.req = request
	return r
}

func (r *RequestManager) SetHeader(key, value string) *RequestManager {
	r.req.Header.Set(key, value)
	return r
}

func (r *RequestManager) DoRequest(object interface{}) ([]byte, int, error) {
	res := fasthttp.AcquireResponse()
	requestErr := r.httpClient.Do(r.req, res)

	body := string(res.Body())

	if DEBUG {
		fmt.Println("BODY ----------------------------------------------------------------------------------------------")
		fmt.Println(body)
		fmt.Println("res.StatusCode()")
		fmt.Println(res.StatusCode())
		fmt.Println("BODY ----------------------------------------------------------------------------------------------")
		fmt.Println("")
	}

	if requestErr != nil {
		fmt.Println(requestErr)
		return nil, 0, requestErr
	}

	if res.StatusCode() != 200 {
		return nil, 0, requestErr
	}

	fmt.Println("body")
	fmt.Println(body)

	if object != nil && string(res.Body()) != "" {
		UnmarshalErr := json.Unmarshal(res.Body(), &object)
		if UnmarshalErr != nil {
			fmt.Println(UnmarshalErr)
			return nil, 0, errors.New("[UnmarshalErr] - " + body)
		}
	}

	fasthttp.ReleaseRequest(r.req)
	fasthttp.ReleaseResponse(res)

	return res.Body(), res.StatusCode(), nil
}
