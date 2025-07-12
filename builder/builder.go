package builder

import (
	"context"
	"deployer/client/config"
	"encoding/json"
	"github.com/docker/docker/api/types/build"
	"github.com/docker/docker/client"
	"github.com/moby/go-archive"
	"io"
	"log"
	"os"
)

var dockerClient *client.Client

func GetClient(ctx context.Context) (*client.Client, error) {
	if dockerClient != nil {
		return dockerClient, nil
	}

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}
	cli.NegotiateAPIVersion(ctx)
	dockerClient = cli
	return dockerClient, nil
}

func BuildImage(configuration *config.Configuration) error {
	ctx := context.Background()
	cli, err := GetClient(ctx)
	if err != nil {
		return err
	}

	wd, err := os.Getwd()
	buildContext, err := archive.TarWithOptions(wd, &archive.TarOptions{})
	if err != nil {
		return err
	}
	defer buildContext.Close()

	buildOptions := build.ImageBuildOptions{
		Tags:       []string{configuration.ImageName},
		Dockerfile: "Dockerfile",
	}
	resp, err := cli.ImageBuild(ctx, buildContext, buildOptions)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	for {
		// Read the response body to get build progress
		var message BuildResponseStreamMessage
		if err := json.NewDecoder(resp.Body).Decode(&message); err != nil {
			if err == io.EOF {
				break // End of stream
			}
			return err
		}

		log.Default().Println(message.Stream)
	}

	return nil
}

func SaveImageToFile(configuration *config.Configuration) (*os.File, error) {
	ctx := context.Background()
	cli, err := GetClient(ctx)
	if err != nil {
		return nil, err
	}

	outputFile, err := os.Create(configuration.Name + ".tar")
	if err != nil {
		return nil, err
	}
	defer outputFile.Close()

	responseBody, err := cli.ImageSave(ctx, []string{configuration.ImageName})
	if err != nil {
		return nil, err
	}
	defer responseBody.Close()

	_, err = io.Copy(outputFile, responseBody)
	if err != nil {
		return nil, err
	}
	return outputFile, nil
}

func ImportImageFromFile(filePath string) error {
	log.Default().Println("Importing image from file:", filePath)
	ctx := context.Background()
	cli, err := GetClient(ctx)
	if err != nil {
		return err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	responseBody, err := cli.ImageLoad(ctx, file)
	if err != nil {
		return err
	}
	defer responseBody.Body.Close()
	io.Copy(io.Discard, responseBody.Body)

	return nil
}

type BuildResponseStreamMessage struct {
	Stream string `json:"stream,omitempty"`
}
