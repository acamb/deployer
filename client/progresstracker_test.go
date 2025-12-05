package client

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintProgress_Scales(t *testing.T) {
	// Setup: 100 MB, 50 MB transferred in 10s -> 50% at ~5 MB/s, Remaining: 10s
	pt := &ProgressTracker{}
	pt.BytesTotal = 100 * 1024 * 1024
	pt.BytesTransferred = 50 * 1024 * 1024
	pt.StartTime = time.Now().Add(-10 * time.Second).Unix()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	pt.printProgress()

	require.NoError(t, w.Close())
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	out := buf.String()

	assert.Contains(t, out, "Progress:  50%")
	assert.Contains(t, out, "Speed: 5 MB/s")
	assert.Contains(t, out, "Remaining: 10s")
}

func TestPrintProgress_RemainingHHMMSS(t *testing.T) {
	// Setup: 360 MB, 120 MB transferred in 60s
	// speed \~2 MB/s -> remaining 240 MB / 2 MB/s = 120s  (00:02:00)
	pt := &ProgressTracker{}
	pt.BytesTotal = 360 * 1024 * 1024
	pt.BytesTransferred = 120 * 1024 * 1024
	pt.StartTime = time.Now().Add(-60 * time.Second).Unix()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	pt.printProgress()

	require.NoError(t, w.Close())
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)

	out := buf.String()

	assert.Contains(t, out, "Progress:")
	assert.Contains(t, out, "Speed: 2 MB/s")
	assert.Contains(t, out, "Remaining: 00:02:00")
}
