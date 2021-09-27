package keygen

import "testing"

func TestGenRsaKey(t *testing.T) {
	type args struct {
		bits    int
		keyname string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "testgenkey",
			args:    args{bits: 500, keyname: "fivehbits"},
			wantErr: false},
		{
			name:    "testgenkey",
			args:    args{bits: 5000, keyname: "../fivethbits"},
			wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := GenRsaKey(tt.args.bits, tt.args.keyname); (err != nil) != tt.wantErr {
				t.Errorf("GenRsaKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
