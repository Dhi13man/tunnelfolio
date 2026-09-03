package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	openVPNReadyMarker   = "Initialization Sequence Completed"
	openVPNDiagnosticCap = 64 << 10
)

type OpenVPNBackendOptions struct {
	Command         string
	ValidateCommand func(string) error
	Inspector       OpenVPNConfigInspector
	ReadyTimeout    time.Duration
	InterruptWait   time.Duration
	TerminateWait   time.Duration
	KillWait        time.Duration
	Log             func(string)
	Env             []string
	ReadIdentity    func(int) (processIdentity, error)
}

type OpenVPNProcessState struct {
	Running        bool
	Ready          bool
	GroupPresent   bool
	UnexpectedExit bool
	LastError      string
}

type OpenVPNBackend struct {
	opts OpenVPNBackendOptions

	mu             sync.Mutex
	proc           *openVPNProcess
	lastExitError  string
	unexpectedExit bool
	exitHandler    func(bool)
}

type openVPNProcess struct {
	cmd             *exec.Cmd
	pid             int
	sessionID       int
	leaderStartTime uint64
	done            chan struct{}
	ready           chan struct{}
	readyOnce       sync.Once
	reader          *os.File

	mu         sync.Mutex
	waitErr    error
	exited     bool
	stopping   bool
	accepted   bool
	unexpected bool
}

func NewOpenVPNBackend(opts OpenVPNBackendOptions) (*OpenVPNBackend, error) {
	if opts.Command == "" {
		return nil, errors.New("OpenVPN command path is required")
	}
	if !strings.HasPrefix(opts.Command, "/") {
		return nil, errors.New("OpenVPN command path must be absolute")
	}
	if opts.ValidateCommand != nil {
		if err := opts.ValidateCommand(opts.Command); err != nil {
			return nil, fmt.Errorf("validate OpenVPN command: %w", err)
		}
	} else if err := validateOpenVPNCommand(opts.Command); err != nil {
		return nil, fmt.Errorf("validate OpenVPN command: %w", err)
	}
	if opts.ReadyTimeout <= 0 {
		opts.ReadyTimeout = 30 * time.Second
	}
	if opts.InterruptWait <= 0 {
		opts.InterruptWait = 3 * time.Second
	}
	if opts.TerminateWait <= 0 {
		opts.TerminateWait = 2 * time.Second
	}
	if opts.KillWait <= 0 {
		opts.KillWait = 2 * time.Second
	}
	if opts.ReadIdentity == nil {
		opts.ReadIdentity = readProcessIdentity
	}
	return &OpenVPNBackend{opts: opts}, nil
}

func (b *OpenVPNBackend) Activate(ctx context.Context, profilePath, providerDir string) error {
	if err := b.opts.Inspector.Inspect(profilePath, providerDir); err != nil {
		return err
	}
	b.mu.Lock()
	if b.proc != nil {
		b.mu.Unlock()
		return errors.New("an OpenVPN process is already owned")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		b.mu.Unlock()
		return fmt.Errorf("create OpenVPN diagnostic pipe: %w", err)
	}
	command := exec.Command(b.opts.Command, "--config", profilePath, "--verb", "3", "--suppress-timestamps")
	command.Dir = providerDir
	command.Stdout, command.Stderr = writer, writer
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
	if b.opts.Env != nil {
		command.Env = append(os.Environ(), b.opts.Env...)
	}
	proc := &openVPNProcess{cmd: command, done: make(chan struct{}), ready: make(chan struct{}), reader: reader}
	if err := command.Start(); err != nil {
		writer.Close()
		reader.Close()
		b.mu.Unlock()
		return fmt.Errorf("start OpenVPN: %w", err)
	}
	proc.pid = command.Process.Pid
	identity, identityErr := b.opts.ReadIdentity(proc.pid)
	if identityErr != nil || identity.processGroup != proc.pid || identity.sessionID != proc.pid {
		_ = syscall.Kill(-proc.pid, syscall.SIGKILL)
		_ = command.Process.Kill()
		_ = command.Wait()
		writer.Close()
		reader.Close()
		b.mu.Unlock()
		if identityErr != nil {
			return fmt.Errorf("capture OpenVPN process identity: %w", identityErr)
		}
		return errors.New("capture OpenVPN process identity: unexpected process group")
	}
	proc.sessionID = identity.sessionID
	proc.leaderStartTime = identity.startTime
	b.proc = proc
	b.mu.Unlock()
	_ = writer.Close()
	go b.drainDiagnostics(proc)
	go b.wait(proc)

	timer := time.NewTimer(b.opts.ReadyTimeout)
	defer timer.Stop()
	select {
	case <-proc.ready:
		proc.mu.Lock()
		if proc.exited {
			proc.mu.Unlock()
			return b.startFailure(proc, "OpenVPN exited during readiness")
		}
		proc.accepted = true
		proc.mu.Unlock()
		b.mu.Lock()
		b.lastExitError = ""
		b.unexpectedExit = false
		b.mu.Unlock()
		return nil
	case <-proc.done:
		return b.startFailure(proc, "OpenVPN exited before readiness")
	case <-timer.C:
		return b.startFailure(proc, "OpenVPN readiness timed out")
	case <-ctx.Done():
		return b.startFailure(proc, "OpenVPN startup canceled: "+ctx.Err().Error())
	}
}

func (b *OpenVPNBackend) startFailure(proc *openVPNProcess, reason string) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), b.cleanupBudget())
	defer cancel()
	cleanupErr := b.stopProcess(cleanupCtx, proc)
	if waitErr := proc.result(); waitErr != nil {
		reason += ": " + safeProcessError(waitErr)
	}
	if cleanupErr != nil {
		return errors.Join(ErrCleanupUnproved, fmt.Errorf("%s; cleanup failed: %w", reason, cleanupErr))
	}
	return errors.New(reason)
}

func (b *OpenVPNBackend) Deactivate(ctx context.Context) error {
	b.mu.Lock()
	proc := b.proc
	b.mu.Unlock()
	if proc == nil {
		return nil
	}
	return b.stopProcess(ctx, proc)
}

func (b *OpenVPNBackend) Shutdown(ctx context.Context) error {
	return b.Deactivate(ctx)
}

func (b *OpenVPNBackend) setUnexpectedExitHandler(handler func(bool)) {
	b.mu.Lock()
	b.exitHandler = handler
	b.mu.Unlock()
}

func (b *OpenVPNBackend) State() OpenVPNProcessState {
	b.mu.Lock()
	proc := b.proc
	lastExitError := b.lastExitError
	unexpectedExit := b.unexpectedExit
	b.mu.Unlock()
	if proc == nil {
		return OpenVPNProcessState{UnexpectedExit: unexpectedExit, LastError: lastExitError}
	}
	proc.mu.Lock()
	state := OpenVPNProcessState{
		Running:        !proc.exited,
		Ready:          channelClosed(proc.ready) && !proc.exited,
		UnexpectedExit: proc.unexpected,
		LastError:      safeProcessError(proc.waitErr),
	}
	if proc.unexpected && state.LastError == "" {
		state.LastError = "process exited unexpectedly"
	}
	proc.mu.Unlock()
	state.GroupPresent = ownedProcessGroupPresent(proc)
	return state
}

func (b *OpenVPNBackend) wait(proc *openVPNProcess) {
	err := proc.cmd.Wait()
	_ = proc.reader.Close()
	proc.mu.Lock()
	proc.waitErr, proc.exited = err, true
	proc.unexpected = proc.accepted && !proc.stopping
	unexpected := proc.unexpected
	proc.mu.Unlock()
	close(proc.done)
	if unexpected {
		message := safeProcessError(err)
		if message == "" {
			message = "process exited unexpectedly"
		}
		b.mu.Lock()
		b.lastExitError = message
		b.unexpectedExit = true
		exitHandler := b.exitHandler
		b.mu.Unlock()
		b.log("OpenVPN process exited unexpectedly: " + message)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), b.cleanupBudget())
		cleanupErr := b.stopProcess(cleanupCtx, proc)
		cancel()
		if cleanupErr != nil {
			b.log("OpenVPN unexpected-exit cleanup failed: " + cleanupErr.Error())
		}
		if exitHandler != nil {
			exitHandler(cleanupErr == nil)
		}
	}
}

func (b *OpenVPNBackend) drainDiagnostics(proc *openVPNProcess) {
	buffer := make([]byte, 2048)
	pending := make([]byte, 0, 4096)
	readinessLine := make([]byte, 0, 128)
	discardReadinessLine := false
	captured := 0
	inspectReadiness := func(chunk []byte, final bool) {
		for len(chunk) > 0 {
			if discardReadinessLine {
				newline := bytes.IndexByte(chunk, '\n')
				if newline < 0 {
					return
				}
				chunk = chunk[newline+1:]
				discardReadinessLine = false
				continue
			}
			newline := bytes.IndexByte(chunk, '\n')
			if newline < 0 {
				readinessLine = append(readinessLine, chunk...)
				if len(readinessLine) > 4096 {
					readinessLine = readinessLine[:0]
					discardReadinessLine = true
				}
				break
			}
			readinessLine = append(readinessLine, chunk[:newline]...)
			if string(bytes.TrimSuffix(readinessLine, []byte{'\r'})) == openVPNReadyMarker {
				proc.readyOnce.Do(func() { close(proc.ready) })
			}
			readinessLine = readinessLine[:0]
			chunk = chunk[newline+1:]
		}
		if final && !discardReadinessLine && string(bytes.TrimSuffix(readinessLine, []byte{'\r'})) == openVPNReadyMarker {
			proc.readyOnce.Do(func() { close(proc.ready) })
		}
	}
	for {
		count, err := proc.reader.Read(buffer)
		if count > 0 {
			chunk := buffer[:count]
			inspectReadiness(chunk, false)
			if captured < openVPNDiagnosticCap {
				remaining := openVPNDiagnosticCap - captured
				if remaining > len(chunk) {
					remaining = len(chunk)
				}
				pending = append(pending, chunk[:remaining]...)
				captured += remaining
			}
			for {
				newline := bytes.IndexByte(pending, '\n')
				if newline < 0 && len(pending) <= 4096 {
					break
				}
				end := newline
				consume := newline + 1
				if newline < 0 {
					end, consume = 4096, 4096
				}
				b.log(redactOpenVPNDiagnostic(string(pending[:end])))
				pending = pending[consume:]
			}
		}
		if err != nil {
			inspectReadiness(nil, true)
			if len(pending) > 0 {
				b.log(redactOpenVPNDiagnostic(string(pending)))
			}
			return
		}
	}
}

func (b *OpenVPNBackend) stopProcess(ctx context.Context, proc *openVPNProcess) error {
	proc.mu.Lock()
	proc.stopping = true
	proc.mu.Unlock()

	stages := []struct {
		signal syscall.Signal
		wait   time.Duration
	}{{syscall.SIGINT, b.opts.InterruptWait}, {syscall.SIGTERM, b.opts.TerminateWait}, {syscall.SIGKILL, b.opts.KillWait}}
	var signalErr error
	for index, stage := range stages {
		if processStopped(proc) {
			return b.releaseProcess(proc)
		}
		if err := signalOwnedProcessGroup(proc, stage.signal); err != nil && signalErr == nil {
			signalErr = err
		}
		waitContext := ctx
		if index == len(stages)-1 {
			waitContext = context.Background()
		}
		if waitForProcessStopped(waitContext, proc, stage.wait) {
			return b.releaseProcess(proc)
		}
	}
	if processStopped(proc) {
		return b.releaseProcess(proc)
	}
	if signalErr != nil {
		return fmt.Errorf("stop OpenVPN process group: %w", signalErr)
	}
	return errors.New("OpenVPN process group was not absent and reaped before cleanup deadline")
}

func (b *OpenVPNBackend) releaseProcess(proc *openVPNProcess) error {
	b.mu.Lock()
	if b.proc == proc {
		b.proc = nil
	}
	b.mu.Unlock()
	return nil
}

func (b *OpenVPNBackend) cleanupBudget() time.Duration {
	return b.opts.InterruptWait + b.opts.TerminateWait + b.opts.KillWait + time.Second
}

func (b *OpenVPNBackend) log(message string) {
	if b.opts.Log != nil && message != "" {
		b.opts.Log(message)
	}
}

func (p *openVPNProcess) result() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waitErr
}

func processStopped(proc *openVPNProcess) bool {
	return channelClosed(proc.done) && !ownedProcessGroupPresent(proc)
}

func waitForProcessStopped(ctx context.Context, proc *openVPNProcess, duration time.Duration) bool {
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		if processStopped(proc) {
			return true
		}
		select {
		case <-ctx.Done():
			return processStopped(proc)
		case <-deadline.C:
			return processStopped(proc)
		case <-poll.C:
		}
	}
}

type processIdentity struct {
	pid          int
	processGroup int
	sessionID    int
	startTime    uint64
}

func readProcessIdentity(pid int) (processIdentity, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return processIdentity{}, err
	}
	closing := bytes.LastIndexByte(data, ')')
	if closing < 0 || closing+2 >= len(data) {
		return processIdentity{}, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(data[closing+2:]))
	if len(fields) < 20 {
		return processIdentity{}, errors.New("incomplete process stat")
	}
	processGroup, err := strconv.Atoi(fields[2])
	if err != nil {
		return processIdentity{}, err
	}
	sessionID, err := strconv.Atoi(fields[3])
	if err != nil {
		return processIdentity{}, err
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return processIdentity{}, err
	}
	return processIdentity{pid: pid, processGroup: processGroup, sessionID: sessionID, startTime: startTime}, nil
}

func ownedProcessGroupMembers(proc *openVPNProcess) ([]processIdentity, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	members := make([]processIdentity, 0, 2)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		identity, err := readProcessIdentity(pid)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		member, err := belongsToOwnedSession(proc, identity)
		if err != nil {
			return nil, err
		}
		if member {
			members = append(members, identity)
		}
	}
	return members, nil
}

func belongsToOwnedSession(proc *openVPNProcess, identity processIdentity) (bool, error) {
	if identity.pid == proc.pid && identity.startTime != proc.leaderStartTime {
		return false, errors.New("OpenVPN session leader identity was reused")
	}
	return identity.sessionID == proc.sessionID, nil
}

func ownedProcessGroupPresent(proc *openVPNProcess) bool {
	members, err := ownedProcessGroupMembers(proc)
	return err != nil || len(members) != 0
}

func signalOwnedProcessGroup(proc *openVPNProcess, signal syscall.Signal) error {
	var result error
	members, err := ownedProcessGroupMembers(proc)
	if err != nil {
		return err
	}
	for _, member := range members {
		pidfd, err := unix.PidfdOpen(member.pid, 0)
		if err != nil {
			if !errors.Is(err, syscall.ESRCH) {
				result = errors.Join(result, err)
			}
			continue
		}
		current, identityErr := readProcessIdentity(member.pid)
		if identityErr == nil && current == member {
			err = unix.PidfdSendSignal(pidfd, unix.Signal(signal), nil, 0)
			if err != nil && !errors.Is(err, syscall.ESRCH) {
				result = errors.Join(result, err)
			}
		}
		_ = unix.Close(pidfd)
	}
	return result
}

func processGroupPresent(pid int) bool {
	err := syscall.Kill(-pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func channelClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func redactOpenVPNDiagnostic(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	lower := strings.ToLower(message)
	if message == openVPNReadyMarker {
		return "OpenVPN initialization completed"
	}
	if strings.Contains(lower, "auth_failed") {
		return "OpenVPN authentication failed"
	}
	if strings.Contains(lower, "tls error") {
		return "OpenVPN TLS negotiation failed"
	}
	return "[redacted OpenVPN diagnostic]"
}

func safeProcessError(err error) string {
	if err == nil {
		return ""
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Sprintf("exit status %d", exitErr.ExitCode())
	}
	return "process wait failed"
}

func validateOpenVPNCommand(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("must be a real executable file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("must not be writable by group or world")
	}
	if os.Geteuid() == 0 && ownerUID(info) != 0 {
		return errors.New("must be owned by root")
	}
	for ancestor := filepath.Dir(path); ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("command ancestor %s must be a real directory", ancestor)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("command ancestor %s must not be writable by group or world", ancestor)
		}
		if os.Geteuid() == 0 && ownerUID(info) != 0 {
			return fmt.Errorf("command ancestor %s must be owned by root", ancestor)
		}
		if ancestor == string(os.PathSeparator) {
			break
		}
	}
	return nil
}
