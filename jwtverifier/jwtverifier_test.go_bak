package jwtverifier

import (
	"fmt"
	"testing"
)

func TestVerifier_Verify(t *testing.T) {
	type fields struct {
		method  string
		keyPath string
	}
	type args struct {
		tokData []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test 1",
			fields: fields{
				method:  "RS256",
				keyPath: "../autogen_rsa_pub.pem"},
			args: args{
				//tokData: []byte(`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJJUCI6IjEyNy4wLjAuMSIsImp0aSI6IjBjYzIyNzg1LTQwYjYtNDk3My05YjA2LTFkM2UxZDEyNjRiMCIsIm15IjoxLCJuYW1lIjoiU0tZIn0.HcKCy2RUaXgN8XXDBJ4HmQ6xKbrV-aqjQI3Wlm0jiE8QNyWvFbCfz7e9kohWZdj1HsLD40F3SQzGLeAvNg5-ETA8BknL8SDmpwkUhS1uPBh1FwCH_XAntZDOp4iOYgb2mp0Jygf099c`),
				//tokData: []byte(`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMjMxMiIsImV4cCI6ODY0MDAsImlhdCI6MTU2NDkyMTE4MCwiaXNzIjoiand0LXNpZ25lciIsImp0aSI6Ijg4YzYyZTA4LTZmMTEtNGNhZS1hYmFkLWQ1NTJkMTUwYWNiMCJ9.KGjoGi3dBfBe_ZOo3hQqAChX1T3KrALZ7nBmTId_li1Uz8D_m6SnyVqU9KwCf4-NUgSLniey5NWvnKJRcQK3KK6YM6nuykAOxq8UdRjcHCpfh-JLk8YKiJSGyJKLb_47kCVVR3LjcI4`),
				tokData: []byte(`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJJUCI6IjEyNy4wLjAuMSIsImlhdCI6MTU2NDkyMTk2MywianRpIjoiN2I1OTY2ZGYtYzI5ZS00NTIyLWE3NTYtZTI3Nzk4MjJlODczIiwibXkiOjEsIm5hbWUiOiJTS1kifQ.Ois1TMOy6D5g0Yp67hC1NYAhvAEcX6hYorwECqMJQqsVgznZFvjYOXc1cXM_mOIWedIfNOrlfSP0aIvrtuXy-SUxP7Rixn0Wzlvu4ri6YymInpD2Rw1pdeJria9N_S2iXTd9Vc98Kx8`),
			},
			wantErr: false,
		},
		// {
		// 	name: "test 2",
		// 	fields: fields{
		// 		method:  "RS256",
		// 		keyPath: "../autogen_rsa_pub.pem"},
		// 	args: args{
		// 		tokData: []byte(`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMjMxMiIsImV4cCI6ODY0MDAsImlhdCI6MTU2NDkyMTE4MCwiaXNzIjoiand0LXNpZ25lciIsImp0aSI6Ijg4YzYyZTA4LTZmMTEtNGNhZS1hYmFkLWQ1NTJkMTUwYWNiMCJ9.KGjoGi3dBfBe_ZOo3hQqAChX1T3KrALZ7nBmTId_li1Uz8D_m6SnyVqU9KwCf4-NUgSLniey5NWvnKJRcQK3KK6YM6nuykAOxq8UdRjcHCpfh-JLk8YKiJSGyJKLb_47kCVVR3LjcI4`),
		// 	),
		// 	wantErr: false,
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewFromPath(tt.fields.method, tt.fields.keyPath)
			if err != nil {
				t.Errorf("Signer NewFromPath() error = %v", err)
				return
			}
			got, err := verifier.Verify(tt.args.tokData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Printf("token:\n %v\n", got)
		})
	}
}
