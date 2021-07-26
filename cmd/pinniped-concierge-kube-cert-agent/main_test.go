// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type errWriter struct{}

func (e errWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("some write error") }

func TestEntrypoint(t *testing.T) {
	for _, tt := range []struct {
		name        string
		args        []string
		env         map[string]string
		failOutput  bool
		wantSleep   time.Duration
		wantLog     string
		wantOutJSON string
		wantFail    bool
	}{
		{
			name:     "missing args",
			args:     []string{},
			wantLog:  "missing subcommand\n",
			wantFail: true,
		},
		{
			name:     "invalid subcommand",
			args:     []string{"/path/to/binary", "invalid"},
			wantLog:  "invalid subcommand \"invalid\"\n",
			wantFail: true,
		},
		{
			name:      "valid sleep",
			args:      []string{"/path/to/binary", "sleep"},
			wantSleep: 2562047*time.Hour + 47*time.Minute + 16*time.Second + 854775807*time.Nanosecond, // math.MaxInt64 nanoseconds, approximately 290 years
		},
		{
			name: "missing cert file",
			args: []string{"/path/to/binary", "print"},
			env: map[string]string{
				"CERT_PATH": "./does/not/exist",
				"KEY_PATH":  "./testdata/test.key",
			},
			wantFail: true,
			wantLog:  "could not read CERT_PATH: open ./does/not/exist: no such file or directory\n",
		},
		{
			name: "missing key file",
			args: []string{"/path/to/binary", "print"},
			env: map[string]string{
				"CERT_PATH": "./testdata/test.crt",
				"KEY_PATH":  "./does/not/exist",
			},
			wantFail: true,
			wantLog:  "could not read KEY_PATH: open ./does/not/exist: no such file or directory\n",
		},
		{
			name: "fail to write output",
			args: []string{"/path/to/binary", "print"},
			env: map[string]string{
				"CERT_PATH": "./testdata/test.crt",
				"KEY_PATH":  "./testdata/test.key",
			},
			failOutput: true,
			wantFail:   true,
			wantLog:    "failed to write output: some write error\n",
		},
		{
			name: "successful print",
			args: []string{"/path/to/binary", "print"},
			env: map[string]string{
				"CERT_PATH": "./testdata/test.crt",
				"KEY_PATH":  "./testdata/test.key",
			},
			wantOutJSON: `{
				"tls.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN5RENDQWJDZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJd01EY3lOVEl4TURReE9Gb1hEVE13TURjeU16SXhNRFF4T0Zvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTDNLCmhZdjJnSVExRHd6aDJjV01pZCtvZkFudkxJZlYyWHY2MXZUTEdwclVJK1hVcUI0L2d0ZjZYNlVObjBMZXR0Mm4KZDhwNHd5N2h3NzNoVS9nZ2R2bVdKdnFCclNqYzNKR2Z5K2tqNjZmS1hYK1BUbGJMN1Fid2lSdmNTcUlYSVdsVgpsSEh4RUNXckVEOGpDdWx3L05WcWZvb2svaDVpTlVDVDl5c3dTSnIvMGZJbWlWbm9UbElvRVlHMmVDTmVqWjVjCmczOXVEM1pUcWQ5WnhXd1NMTG5JKzJrcEpuWkJQY2QxWlE4QVFxekRnWnRZUkNxYWNuNWdja1FVS1pXS1FseG8KRWZ0NmcxWEhKb3VBV0FadzdoRXRrMHY4ckcwL2VLRjd3YW14Rmk2QkZWbGJqV0JzQjRUOXJBcGJkQldUS2VDSgpIdjhmdjVSTUZTenBUM3V6VE84Q0F3RUFBYU1qTUNFd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFDaDVSaGJ4cUplK1ovZ2MxN2NaaEtObWRpd3UKSTJwTHAzUUJmd3ZOK1dibWFqencvN3JZaFkwZDhKWVZUSnpYU0NQV2k2VUFLeEF0WE9MRjhXSUlmOWkzOW42Ugp1S09CR1cxNEZ6ekd5UkppRDNxYUcvSlR2RVcrU0xod2w2OE5kcjVMSFNuYnVnQXFxMzFhYmNReTZabDl2NUE4CkpLQzk3TGovU244cmo3b3BLeTRXM29xN05DUXNBYjB6aDRJbGxSRjZVdlNuSnlTZnNnN3hkWEhIcHhZREh0T1MKWGNPdTV5U1VJWlRnRmU5UmZlVVpsR1o1eG4wY2tNbFE3cVcyV3gxcTBPVld3NXVzNE50a0dxS3JIRzRUbjFYNwp1d28vWXl0bjVzRHhyRHYxL29paTZBWk9Dc1RQcmU0b0Qzd3o0bm1WekNWSmNncnFINFEyNGhUOFdOZz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
				"tls.key": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb2dJQkFBS0NBUUVBdmNxRmkvYUFoRFVQRE9IWnhZeUozNmg4Q2U4c2g5WFplL3JXOU1zYW10UWo1ZFNvCkhqK0MxL3BmcFEyZlF0NjIzYWQzeW5qREx1SER2ZUZUK0NCMitaWW0rb0d0S056Y2taL0w2U1BycDhwZGY0OU8KVnN2dEJ2Q0pHOXhLb2hjaGFWV1VjZkVRSmFzUVB5TUs2WEQ4MVdwK2lpVCtIbUkxUUpQM0t6Qkltdi9SOGlhSgpXZWhPVWlnUmdiWjRJMTZObmx5RGYyNFBkbE9wMzFuRmJCSXN1Y2o3YVNrbWRrRTl4M1ZsRHdCQ3JNT0JtMWhFCktwcHlmbUJ5UkJRcGxZcENYR2dSKzNxRFZjY21pNEJZQm5EdUVTMlRTL3lzYlQ5NG9YdkJxYkVXTG9FVldWdU4KWUd3SGhQMnNDbHQwRlpNcDRJa2UveCsvbEV3VkxPbFBlN05NN3dJREFRQUJBb0lCQUZDMXRVRW1ITlVjTTBCSgpNM0Q5S1F6Qis2M0YxbXdWbHgxUU9PVjFFZVZSM2NvNU94MVI2UFNyOXN5Y0ZHUTlqZ3FJMHpwNVRKZTlUcDZMCkdraGtsZlBoMU1Xbks5bzZ3bG56V0tYV3JycDJKbmkrbXBQeXVPUEFtcTRNYW5pdjJYZVArMGJST3dxcHlvanYKQUE3eUM3TStUSDIyNlpKR05WczNFVjkrY3dIbWwweXV6QmZJSm4vcnYvdzJnK1dSS00vTUMwUzdrMmQ4YlJsQQpOeWNLVkdBR0JoS1RsdGpvVllPZWg2YUhFcFNqSzh6ZmFlUGpvNWRZSnZvVklsaTYwWUNnY0pPVS84alhUK05wCjFGbTd0UnZBdGozcFVwMFNxZGFmMlJVemg5amZKcDJWRkNIdVNKNlRQcUFyT3lRb2p0TWNUSEYwVGlXN3hySFAKeE9DUklBRUNnWUVBd0dCUFU3dmR0aE1KQmcrT1JVb0dRUWFJdFRlSnZRd0lxSnZiS0Qyb3NwNGpoUzFkR1pCdwpXMzBHS0VjL2dkOEpOdE9xOUJCbk1pY1BGN2hrdHV5K2JTUHY0MVhQdWQ2N3JTU083VHN3MjBDMTBnRlJxMDZCCnpJSldGQVVxSzNJa3ZWYzNWRG10U0xTRG94NFFaL0JkcWFNbFE1eTVKQ3NDNWtUaG1rWkZsTzhDZ1lFQS9JOVgKWUhpNlJpb01KRTFmcU9ISkw0RERqbGV6bWN1UnJEN2ZFNUluS2J0SloySmhHWU9YL0MwS1huSFRPV1RDRHh4TgpGQnZwdkQ2WHY1bzNQaEI5WjZrMmZxdko0R1M4dXJrRy9LVTR4Y0MrYmFrKzlhdmE4b2FpU3FHMTZ6RDlOSDJQCmpKNjBOcmJMbDFKMHBVOWZpd3VGVlVLSjRoRFpPZk45UnFZZHlBRUNnWUFWd284V2hKaUdnTTZ6ZmN6MDczT1gKcFZxUFRQSHFqVkxwWjMrNXBJZlJkR3ZHSTZSMVFNNUV1dmFZVmI3TVBPTTQ3V1pYNXdjVk9DL1AyZzZpVmxNUAoyMUhHSUMyMzg0YTlCZmFZeE9vNDBxLytTaUhudzZDUTlta3dLSWxsa3Fxdk5BOVJHcGtNTVViMmkyOEZvcjJsCmM0dkNneGE2RFpkdFhuczZUUnFQeHdLQmdDZlk1Y3hPdi9UNkJWaGs3TWJVZU0ySjMxREIvWkF5VWhWL0Jlc3MKa0FsQmgxOU1ZazJJT1o2TDdLcmlBcFYzbERhV0hJTWp0RWtEQnlZdnlxOThJbzBNWVpDeXdmTXBjYTEwSytvSQpsMkI3L0krSXVHcENaeFVFc081ZGZUcFNUR0RQdnFwTkQ5bmlGVlVXcVZpN29UTnE2ZXA5eVF0bDVTQURqcXhxCjRTQUJBb0dBSW0waFVnMXd0Y1M0NmNHTHk2UElrUE01dG9jVFNnaHR6NHZGc3VrL2k0UUE5R0JvQk8yZ0g2dHkKK2tKSG1lYVh0MmRtZ3lTcDBRQVdpdDVVbGNlRXVtQjBOWG5BZEpaUXhlR1NGU3lZa0RXaHdYZDh3RGNlS28vMQpMZkNVNkRrOElOL1NzcHBWVVdYUTJybE9SdnhsckhlQ2lvOG8wa1M5WWl1NTVXTVlnNGc9Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="
			}`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			testLog := log.New(&logBuf, "", 0)
			exited := "exiting via fatal"
			fail = func(format string, v ...interface{}) {
				testLog.Printf(format, v...)
				panic(exited)
			}

			var sawSleep time.Duration
			sleep = func(d time.Duration) { sawSleep = d }

			var sawOutput bytes.Buffer
			out = &sawOutput
			if tt.failOutput {
				out = &errWriter{}
			}

			os.Args = tt.args
			getenv = func(key string) string { return tt.env[key] }
			if tt.wantFail {
				require.PanicsWithValue(t, exited, main)
			} else {
				require.NotPanics(t, main)
			}
			require.Equal(t, tt.wantSleep.String(), sawSleep.String())
			require.Equal(t, tt.wantLog, logBuf.String())
			if tt.wantOutJSON == "" {
				require.Empty(t, sawOutput.String())
			} else {
				require.JSONEq(t, tt.wantOutJSON, sawOutput.String())
			}
		})
	}
}
