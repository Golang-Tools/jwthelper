package jwtverifier_serv

import (
	"context"

	"github.com/Golang-Tools/jwthelper/jwt_pb"
	"github.com/Golang-Tools/jwthelper/jwtverifier_pb"
	"github.com/Golang-Tools/jwthelper/verifyoptions"
	log "github.com/Golang-Tools/loggerhelper"
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

//Meta 查看签名器的元信息
func (s *Server) Meta(ctx context.Context, in *jwtverifier_pb.MetaRequest) (*jwtverifier_pb.MetaResponse, error) {
	log.Debug("Meta get message", log.Dict{"in": in})
	meta, err := s.verifier.Meta()
	if err != nil {
		return nil, err
	}
	res := &jwtverifier_pb.MetaResponse{
		Status: &jwt_pb.ResponseStatus{
			Status: jwt_pb.ResponseStatus_SUCCEED,
		},
		Data: meta,
	}
	log.Debug("Meta send resp", log.Dict{"result": res})
	return res, nil
}

//Verify 校验签名
func (s *Server) Verify(ctx context.Context, in *jwtverifier_pb.VerifyRequest) (*jwtverifier_pb.VerifyResponse, error) {
	log.Debug("Sign get message", log.Dict{"in": in})
	opts := []verifyoptions.VerifyOption{}
	if in.CheckMatchSub != "" {
		opts = append(opts, verifyoptions.WithSUBMustBe(in.CheckMatchSub))
	}
	if in.CheckMatchAud != "" {
		opts = append(opts, verifyoptions.WithAUDMustHas(in.CheckMatchAud))
	}
	if in.CheckMatchIss != nil && len(in.CheckMatchIss) > 0 {
		opts = append(opts, verifyoptions.WithIssMustIn(in.CheckMatchIss...))
	}
	if in.NotCheckRefreshTokenAud {
		opts = append(opts, verifyoptions.WithNotCheckRefreshTokenAUD())
	}
	if in.NotCheckRefreshTokenJti {
		opts = append(opts, verifyoptions.WithNotCheckRefreshTokenJTI())
	}
	payload := map[string]interface{}{}
	jti, timeleft, err := s.verifier.Verify(in.Token, &payload, opts...)
	if err != nil {
		return nil, err
	}
	payloadb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	res := &jwtverifier_pb.VerifyResponse{
		Status: &jwt_pb.ResponseStatus{
			Status: jwt_pb.ResponseStatus_SUCCEED,
		},
		Jti:      jti,
		TimeLeft: int64(timeleft),
		Payload:  payloadb,
	}
	log.Debug("Verify send resp", log.Dict{"result": res})
	return res, nil
}
