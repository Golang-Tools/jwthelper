package sdk

type testPayLoad struct {
	A int     `json:"a"`
	B string  `json:"b,omitempty"`
	C float32 `json:"-"`
}
