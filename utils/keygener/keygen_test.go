package keygener

import "testing"

func TestGenKey(t *testing.T) {
	type args struct {
		algo    AlgoType
		keyname string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "test_gen_rsa_key",
			args:    args{algo: AlgoType_RSA, keyname: "newkey"},
			wantErr: false},
		{
			name:    "test_gen_ec_key",
			args:    args{algo: AlgoType_ECDSA, keyname: "newkey"},
			wantErr: false},
		{
			name:    "test_gen_ed_key",
			args:    args{algo: AlgoType_ED25519, keyname: "newkey"},
			wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := GenKey(tt.args.algo, tt.args.keyname)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
