package signerserv

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Golang-Tools/jwthelper/contrib/pb/jwtpb"
	"github.com/Golang-Tools/jwthelper/contrib/pb/pbconv"
	"github.com/Golang-Tools/jwthelper/contrib/pb/signerpb"
	"github.com/Golang-Tools/jwthelper/v4/exceptions"
	"github.com/Golang-Tools/jwthelper/v4/signoptions"
	log "github.com/Golang-Tools/loggerhelper/v4"
	"github.com/Golang-Tools/optparams"
)

// Meta 查看签名器的元信息
func (s *Server) Meta(ctx context.Context, in *signerpb.MetaRequest) (*signerpb.MetaResponse, error) {
	log.Debug("Meta get message", log.Dict{"in": in})
	meta, err := s.signer.Meta(ctx)
	if err != nil {
		return nil, err
	}
	res := &signerpb.MetaResponse{
		Status: &jwtpb.ResponseStatus{
			Status: jwtpb.ResponseStatus_SUCCEED,
		},
		Data: pbconv.SignerMetaToPB(meta),
	}

	log.Debug("Meta send resp", log.Dict{"result": res})
	return res, nil
}

// Sign 用签名器签名
func (s *Server) Sign(ctx context.Context, in *signerpb.SignRequest) (*signerpb.SignResponse, error) {
	log.Debug("Sign get message", log.Dict{"in": in})
	payload := map[string]interface{}{}
	err := json.Unmarshal(in.Payload, &payload)
	if err != nil {
		return nil, err
	}
	opts := []optparams.Option[signoptions.SignOptions]{}
	if in.Sub != "" {
		opts = append(opts, signoptions.WithSub(in.Sub))
	}
	if in.Exp > 0 {
		opts = append(opts, signoptions.WithExpAt(time.Unix(in.Exp, 0)))
	}
	if in.Nbf > 0 {
		opts = append(opts, signoptions.WithNbf(in.Nbf))
	}
	if in.Refreshexp > 0 {
		opts = append(opts, signoptions.WithRefreshExpAt(time.Unix(in.Refreshexp, 0)))
	}
	if in.Jti != "" {
		opts = append(opts, signoptions.WithJTI(in.Jti))
	}
	if in.Aud != nil && len(in.Aud) > 0 {
		opts = append(opts, signoptions.WithAud(in.Aud...))
	}
	token, err := s.signer.Sign(ctx, payload, opts...)
	if err != nil {
		return &signerpb.SignResponse{
			Status: &jwtpb.ResponseStatus{
				Status:    jwtpb.ResponseStatus_FAILED,
				Message:   err.Error(),
				ErrorKind: exceptions.KindOf(err),
			},
		}, nil
	}
	res := &signerpb.SignResponse{
		Status: &jwtpb.ResponseStatus{
			Status: jwtpb.ResponseStatus_SUCCEED,
		},
		Token: pbconv.TokenToPB(token),
	}
	log.Debug("Sign send resp", log.Dict{"result": res})
	return res, nil
}
