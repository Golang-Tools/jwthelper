package jwtsigner_serv

import (
	"context"
	"time"

	"github.com/Golang-Tools/jwthelper/v2/jwt_pb"
	"github.com/Golang-Tools/jwthelper/v2/jwtsigner_pb"
	"github.com/Golang-Tools/jwthelper/v2/signoptions"
	log "github.com/Golang-Tools/loggerhelper/v2"
	"github.com/Golang-Tools/optparams"
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

//Meta 查看签名器的元信息
func (s *Server) Meta(ctx context.Context, in *jwtsigner_pb.MetaRequest) (*jwtsigner_pb.MetaResponse, error) {
	log.Debug("Meta get message", log.Dict{"in": in})
	meta, err := s.signer.Meta()
	if err != nil {
		return nil, err
	}
	res := &jwtsigner_pb.MetaResponse{
		Status: &jwt_pb.ResponseStatus{
			Status: jwt_pb.ResponseStatus_SUCCEED,
		},
		Data: meta,
	}

	log.Debug("Meta send resp", log.Dict{"result": res})
	return res, nil
}

//Sign 用签名器签名
func (s *Server) Sign(ctx context.Context, in *jwtsigner_pb.SignRequest) (*jwtsigner_pb.SignResponse, error) {
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
		opts = append(opts, signoptions.WithExpAt(time.Unix(in.Nbf, 0)))
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
	token, err := s.signer.Sign(payload, opts...)
	if err != nil {
		return nil, err
	}
	res := &jwtsigner_pb.SignResponse{
		Status: &jwt_pb.ResponseStatus{
			Status: jwt_pb.ResponseStatus_SUCCEED,
		},
		Token: token,
	}
	log.Debug("Sign send resp", log.Dict{"result": res})
	return res, nil
}
