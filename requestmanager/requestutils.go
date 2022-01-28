package requestmanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func ParseAndValidateRequest(body []byte, status int, model interface{}) error {

	if status == http.StatusUnauthorized {
		fmt.Println("unauthorized")
		return errors.New("unauthorized")
	}

	if status != http.StatusOK {
		fmt.Println("request error")
		return errors.New("request error")
	}

	if string(body) != "" {
		err := json.Unmarshal(body, &model)
		if err != nil {
			return err
		}
	}

	//fmt.Println(string(body))

	return nil
}
