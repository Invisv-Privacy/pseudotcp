package integration

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/invisv-privacy/pseudotcp/internal/testutils"

	tc "github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

const h2oServiceName string = "h2o"

var containerGateway string
var containerIP string

var logger *slog.Logger

func TestMain(m *testing.M) {
	level := slog.LevelDebug
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// Start the h2o docker container
	identifier := tc.StackIdentifier("h2o_test")
	composeFile := fmt.Sprintf("%s/docker-compose.yml", testutils.RootDir())
	compose, err := tc.NewDockerComposeWith(tc.WithStackFiles(composeFile), identifier)
	if err != nil {
		log.Fatalf("error in NewDockerComposeAPIWith: %v", err)
	}

	defer func() {
		if err := compose.Down(
			context.Background(),
			tc.RemoveOrphans(true),
			tc.RemoveImagesLocal,
		); err != nil {
			log.Fatalf("error in compose.Down: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stack := compose.WaitForService(h2oServiceName,
		// The h2o conf provides a /status endpoint listening on
		// non-TLS port 8081
		wait.
			NewHTTPStrategy("/status").
			WithPort("8081/tcp").
			WithStartupTimeout(10*time.Second),
	)

	if err := stack.Up(ctx, tc.Wait(true)); err != nil {
		log.Fatalf("error in compose.Up(): %v", err)
	}

	container, err := stack.ServiceContainer(ctx, h2oServiceName)
	if err != nil {
		log.Fatalf("error in stack.ServiceContainer: %v", err)
	}

	logger.Info("compose up", "services", stack.Services(), "container", container)

	// Kind of awkward network info parsing here.
	// We need the container's gateway IP because that _should_ be the address the host can ListenUDP on where the container can access it.
	containerIPs, err := container.ContainerIPs(ctx)
	if err != nil {
		log.Fatalf("error in container.ContainerIPs: %v", err)
	}

	containerIP = containerIPs[0]
	containerIPSplit := strings.Split(containerIP, ".")
	containerNet := strings.Join(containerIPSplit[:len(containerIPSplit)-1], ".")

	containerGateway = fmt.Sprintf("%v.1", containerNet)

	m.Run()
}
