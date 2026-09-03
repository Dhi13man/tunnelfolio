package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Dhi13man/tunnelfolio/internal/profiles"
	"github.com/Dhi13man/tunnelfolio/internal/securefs"
)

const maxMultipartField = 1 << 20

var (
	errInvalidMultipart = errors.New("invalid multipart request")
	errImportStaging    = errors.New("import staging failed")
)

type stagedMultipart struct {
	files  []profiles.ImportFile
	fields map[string][]byte
	root   *os.File
	dir    *os.File
	name   string
	uid    int
}

func stageImportMultipart(c *gin.Context, runtimeDir string, allowedFields map[string]bool) (*stagedMultipart, error) {
	mediaType, parameters, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" || parameters["boundary"] == "" {
		return nil, errUnsupportedMediaType
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, profiles.MaxImportRequest)
	uid := os.Geteuid()
	if err := securefs.EnsurePrivateDir(runtimeDir, uid); err != nil {
		return nil, fmt.Errorf("%w: prepare runtime directory", errImportStaging)
	}
	root, err := securefs.OpenPrivateDir(runtimeDir, uid)
	if err != nil {
		return nil, fmt.Errorf("%w: open runtime directory", errImportStaging)
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("%w: name request", errImportStaging)
	}
	name := "request-" + hex.EncodeToString(random[:])
	directory, err := securefs.MkdirExclusive(root, name, uid)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("%w: create request directory", errImportStaging)
	}
	staged := &stagedMultipart{fields: make(map[string][]byte), root: root, dir: directory, name: name, uid: uid}
	reader := multipart.NewReader(c.Request.Body, parameters["boundary"])
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			staged.Cleanup()
			var limitError *http.MaxBytesError
			if errors.As(err, &limitError) {
				return nil, errRequestTooLarge
			}
			return nil, fmt.Errorf("%w: body could not be read", errInvalidMultipart)
		}
		field := part.FormName()
		if field == "files" {
			if err := staged.stageFile(part); err != nil {
				_ = part.Close()
				staged.Cleanup()
				return nil, err
			}
		} else {
			if !allowedFields[field] || field == "" || part.FileName() != "" {
				_ = part.Close()
				staged.Cleanup()
				return nil, fmt.Errorf("%w: unknown part", errInvalidMultipart)
			}
			if _, duplicate := staged.fields[field]; duplicate {
				_ = part.Close()
				staged.Cleanup()
				return nil, fmt.Errorf("%w: duplicate part", errInvalidMultipart)
			}
			data, err := io.ReadAll(io.LimitReader(part, maxMultipartField+1))
			if err != nil {
				_ = part.Close()
				staged.Cleanup()
				var limitError *http.MaxBytesError
				if errors.As(err, &limitError) {
					return nil, errRequestTooLarge
				}
				return nil, fmt.Errorf("%w: field could not be read", errInvalidMultipart)
			}
			if len(data) > maxMultipartField {
				_ = part.Close()
				staged.Cleanup()
				return nil, errRequestTooLarge
			}
			staged.fields[field] = data
		}
		_ = part.Close()
	}
	if len(staged.files) == 0 {
		staged.Cleanup()
		return nil, fmt.Errorf("%w: no profile files", errInvalidMultipart)
	}
	return staged, nil
}

func (s *stagedMultipart) stageFile(part *multipart.Part) error {
	if len(s.files) == profiles.MaxImportFiles {
		return errRequestTooLarge
	}
	_, parameters, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
	if err != nil {
		return fmt.Errorf("%w: malformed file disposition", errInvalidMultipart)
	}
	filename := parameters["filename"]
	if err := profiles.ValidateOriginalFilename(filename); err != nil {
		return fmt.Errorf("%w: invalid profile filename", errInvalidMultipart)
	}
	name := fmt.Sprintf("%03d.profile", len(s.files))
	written, err := securefs.WriteExclusiveFrom(s.dir, name, part, profiles.MaxProfileBytes, s.uid)
	if written > profiles.MaxProfileBytes {
		return errRequestTooLarge
	}
	if err != nil {
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			return errRequestTooLarge
		}
		return fmt.Errorf("%w: write profile", errImportStaging)
	}
	data, err := securefs.ReadFileAt(s.dir, name, profiles.MaxProfileBytes, s.uid)
	if err != nil {
		return fmt.Errorf("%w: read staged profile", errImportStaging)
	}
	s.files = append(s.files, profiles.ImportFile{Name: filename, Bytes: data})
	return nil
}

func (s *stagedMultipart) applyOverrides() error {
	data, exists := s.fields["protocol_overrides"]
	if !exists {
		return nil
	}
	var overrides map[string]string
	if err := decodeStrictJSON(data, &overrides, true); err != nil {
		return errors.New("protocol overrides are invalid")
	}
	for ordinalText, protocol := range overrides {
		ordinal, err := strconv.Atoi(ordinalText)
		if err != nil || ordinal < 0 || ordinal >= len(s.files) || strconv.Itoa(ordinal) != ordinalText || !profiles.ValidProtocol(protocol) {
			return errors.New("protocol overrides are invalid")
		}
		s.files[ordinal].ProtocolOverride = protocol
	}
	return nil
}

func (s *stagedMultipart) Cleanup() {
	if s == nil {
		return
	}
	if s.dir != nil {
		_ = s.dir.Close()
		s.dir = nil
	}
	if s.root != nil {
		_ = securefs.RemoveTreeAt(s.root, s.name, s.uid)
		_ = securefs.Sync(s.root)
		_ = s.root.Close()
		s.root = nil
	}
}

func exactTextField(fields map[string][]byte, name string, maximum int) (string, error) {
	data, exists := fields[name]
	if !exists || len(data) == 0 || len(data) > maximum {
		return "", fmt.Errorf("%s is required", strings.ReplaceAll(name, "_", " "))
	}
	value := string(data)
	if strings.TrimSpace(value) != value {
		return "", fmt.Errorf("%s is invalid", strings.ReplaceAll(name, "_", " "))
	}
	return value, nil
}
