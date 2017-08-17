package container

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

type containerConfig struct {
	Config           container.Config
	HostConfig       container.HostConfig
	NetworkingConfig network.NetworkingConfig
}

// rmContainer is effectively `docker rm`.
func rmContainer(ctx context.Context, cli client.APIClient, name string, force bool) error {
	return cli.ContainerRemove(ctx, name, types.ContainerRemoveOptions{
		Force: force,
	})
}

// runDetachedContainer is effectively a simplified version of `docker run -d`.
func runDetachedContainer(ctx context.Context, cli client.APIClient, config containerConfig, name string) (string, error) {
	// Disable all attaching.
	config.Config.AttachStdin = false
	config.Config.AttachStdout = false
	config.Config.AttachStderr = false
	config.Config.StdinOnce = false

	// Create the container.
	createResponse, err := cli.ContainerCreate(ctx, &config.Config, &config.HostConfig, &config.NetworkingConfig, name)
	if err != nil {
		return "", err
	}

	// Create a filter for all the events relating to our container.
	containerID := createResponse.ID
	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("container", containerID)

	// Listen for container events for our container, do this before start to avoid races.
	eventCtx, cancelFn := context.WithCancel(ctx)
	eventsChan, errChan := cli.Events(eventCtx, types.EventsOptions{
		Filters: filter,
	})
	defer cancelFn()

	// Start the container.
	if err := cli.ContainerStart(ctx, containerID, types.ContainerStartOptions{}); err != nil {
		return "", err
	}

	// Wait until we see a "die" or "start" event. If the "start" fails,
	// weirdly we don't see a die event, so we also have to have a timeout.
loop:
	for {
		select {
		case err := <-errChan:
			return "", err
		case event := <-eventsChan:
			switch event.Action {
			case "die":
				return "", fmt.Errorf("container %d died prematurely", containerID)
			case "start":
				break loop
			}
		case <-time.After(500 * time.Milliseconds):
			return "", fmt.Errorf("timed out waiting for container %d to start", containerID)
		}
	}

	return containerID, nil
}
