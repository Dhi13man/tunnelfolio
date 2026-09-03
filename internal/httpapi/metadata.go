package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/Dhi13man/tunnelfolio/internal/profiles"
)

type metadataPatchRequest struct {
	DisplayName json.RawMessage `json:"display_name"`
	Group       json.RawMessage `json:"group"`
	Location    json.RawMessage `json:"location"`
}

var errMalformedMetadataPatch = errors.New("malformed metadata patch")

func decodeMetadataPatch(request *http.Request) (profiles.MetadataPatch, error) {
	var raw metadataPatchRequest
	if err := decodeJSONRequest(request, &raw); err != nil {
		return profiles.MetadataPatch{}, errors.Join(errMalformedMetadataPatch, err)
	}
	var patch profiles.MetadataPatch
	set := 0
	if raw.DisplayName != nil {
		value, err := requiredString(raw.DisplayName)
		if err != nil {
			return profiles.MetadataPatch{}, err
		}
		patch.DisplayName, set = &value, set+1
	}
	if raw.Group != nil {
		value, err := requiredString(raw.Group)
		if err != nil {
			return profiles.MetadataPatch{}, err
		}
		patch.Group, set = &value, set+1
	}
	if raw.Location != nil {
		if bytes.Equal(bytes.TrimSpace(raw.Location), []byte("null")) {
			patch.ClearLocation = true
		} else {
			value, err := requiredString(raw.Location)
			if err != nil {
				return profiles.MetadataPatch{}, err
			}
			patch.Location = &value
		}
		set++
	}
	if set == 0 {
		return profiles.MetadataPatch{}, errors.New("metadata patch is empty")
	}
	return patch, nil
}

func requiredString(data json.RawMessage) (string, error) {
	var value string
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", errors.New("field must contain one string")
	}
	return value, nil
}

func parseRevision(value string) (uint64, error) { return strconv.ParseUint(value, 10, 64) }

func formatInt(value int) string { return strconv.Itoa(value) }

func requestBodyEmpty(request *http.Request) bool {
	if request == nil || request.Body == nil || request.Body == http.NoBody {
		return true
	}
	var probe [1]byte
	count, err := request.Body.Read(probe[:])
	return count == 0 && errors.Is(err, io.EOF)
}
