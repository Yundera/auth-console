// Package dockerx is the console's only use of the Docker engine: running host
// verbs in a one-shot privileged container. Ported from mesh-console's dockerx
// (RunOnHost), with stdout and stderr kept apart — every verb here answers JSON
// on stdout while the scripts log to stderr — and with verbs queued in-process
// instead of refused, because a single page load runs several of them.
package dockerx

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
)

type Client struct {
	cli *client.Client
	// mu serialises this process's verbs. The runner name is fixed, so two
	// concurrent verbs would otherwise collide; queueing them is what lets the
	// Account page load users and onboarding status at the same time.
	mu sync.Mutex
}

func New() (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &Client{cli: cli}, nil
}

// ImageOf returns the image a container was created from — how the runner
// finds this console's own image without being told.
func (c *Client) ImageOf(ctx context.Context, name string) (string, error) {
	info, err := c.cli.ContainerInspect(ctx, name)
	if err != nil {
		return "", err
	}
	if info.Config == nil || info.Config.Image == "" {
		return "", errors.New("container has no image")
	}
	return info.Config.Image, nil
}

// RunnerName is fixed so that "is a host verb already running?" is a name
// lookup, and at most one runs at a time.
const RunnerName = "auth-console-runner"

// ErrBusy means a runner this process does not own (a previous container's,
// mid-recreate) is still running, or the queue wait expired.
var ErrBusy = errors.New("another host action is still running")

// QueueWait bounds how long a verb waits for the one before it.
const QueueWait = 60 * time.Second

// runnerBusy reports whether a runner container is currently running. A
// leftover stopped one (a verb whose cleanup was cut short) is removed so it
// cannot block the next verb.
func (c *Client) runnerBusy(ctx context.Context) (bool, error) {
	info, err := c.cli.ContainerInspect(ctx, RunnerName)
	if errdefs.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.State != nil && info.State.Running {
		return true, nil
	}
	_ = c.cli.ContainerRemove(ctx, RunnerName, container.RemoveOptions{Force: true})
	return false, nil
}

// RunResult is a verb's outcome. Stdout carries the verb's JSON answer and may
// hold a one-time password: it is never logged.
type RunResult struct {
	ExitCode int64
	Stdout   string
	Stderr   string
}

// RunOnHost runs argv in the HOST's mount, UTS, IPC, network and PID
// namespaces, from a one-shot container of image, and waits for it.
//
// Why a container and not SSH (settings-center-app's route): a FOSS box has no
// admin user, sshd config or sudoers set up for us, on purpose. This process
// already holds the Docker socket, which is root on the host, so a privileged
// sibling adds no power — it only gives the verb the host's view.
//
// ctx must NOT be the HTTP request's: a client that navigates away would
// cancel the wait and the deferred force-remove would kill the verb half way
// through (a users_database.yml write, an authorized_keys rewrite).
func (c *Client) RunOnHost(ctx context.Context, image string, argv []string) (*RunResult, error) {
	if !c.lock(ctx) {
		return nil, ErrBusy
	}
	defer c.mu.Unlock()

	if busy, err := c.waitForeignRunner(ctx); err != nil {
		return nil, err
	} else if busy {
		return nil, ErrBusy
	}
	// Entrypoint is set, not cleared: an empty override is dropped by the API
	// (omitempty) and the image's own entrypoint — the console binary — would run
	// with this argv as its arguments.
	created, err := c.cli.ContainerCreate(ctx,
		&container.Config{
			Image:      image,
			Entrypoint: []string{"nsenter"},
			Cmd:        append([]string{"-t", "1", "-m", "-u", "-i", "-n", "-p", "--"}, argv...),
			Labels:     map[string]string{"auth-console.runner": "true"},
		},
		&container.HostConfig{
			Privileged:  true,
			PidMode:     "host",
			NetworkMode: "none",
		}, nil, nil, RunnerName)
	if err != nil {
		if errdefs.IsConflict(err) {
			return nil, ErrBusy
		}
		return nil, err
	}
	defer func() {
		_ = c.cli.ContainerRemove(context.WithoutCancel(ctx), created.ID, container.RemoveOptions{Force: true})
	}()
	if err := c.cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		return nil, err
	}

	statusCh, errCh := c.cli.ContainerWait(ctx, created.ID, container.WaitConditionNotRunning)
	var code int64
	select {
	case err := <-errCh:
		if err != nil {
			return nil, err
		}
	case st := <-statusCh:
		code = st.StatusCode
	}
	rc, err := c.cli.ContainerLogs(ctx, created.ID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return &RunResult{ExitCode: code}, nil
	}
	defer rc.Close()
	var stdout, stderr bytes.Buffer
	_, _ = stdcopy.StdCopy(&stdout, &stderr, rc)
	return &RunResult{ExitCode: code, Stdout: stdout.String(), Stderr: tail(stderr.String(), 8000)}, nil
}

// lock takes the in-process queue, giving up after QueueWait or when ctx ends.
func (c *Client) lock(ctx context.Context) bool {
	deadline := time.Now().Add(QueueWait)
	for {
		if c.mu.TryLock() {
			return true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitForeignRunner waits briefly for a runner this process did not start
// (one left by the previous container of this service) to finish.
func (c *Client) waitForeignRunner(ctx context.Context) (bool, error) {
	for i := 0; i < 20; i++ {
		busy, err := c.runnerBusy(ctx)
		if err != nil || !busy {
			return busy, err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return true, nil
}

func tail(s string, n int) string {
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}
