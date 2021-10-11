package jwtverifier_serv

import (
	"context"

	"github.com/Golang-Tools/jwthelper/exceptions"
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
	res := &jwtverifier_pb.VerifyResponse{}
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
	status, err := s.verifier.Verify(in.Token, &payload, opts...)
	payloadb, err1 := json.Marshal(payload)
	if err1 != nil {
		res.Status = &jwt_pb.ResponseStatus{
			Status:  jwt_pb.ResponseStatus_FAILED,
			Message: "get payload error",
		}
		return res, err1
	}
	if err == nil {
		res.Status = &jwt_pb.ResponseStatus{
			Status: jwt_pb.ResponseStatus_SUCCEED,
		}
		res.JwtStatus = status
		res.Payload = payloadb
		log.Debug("Verify send resp", log.Dict{"result": res})
		return res, nil
	} else {
		if err == exceptions.ErrValidationErrorExpired {
			if status != nil {
				res.Status = &jwt_pb.ResponseStatus{
					Status: jwt_pb.ResponseStatus_SUCCEED,
				}
				res.JwtStatus = status
				res.Payload = payloadb
				log.Debug("Verify send resp", log.Dict{"result": res})
				return res, err
			} else {
				res.Status = &jwt_pb.ResponseStatus{
					Status:  jwt_pb.ResponseStatus_FAILED,
					Message: "olny access token and is expored",
				}
				res.Payload = payloadb
				log.Debug("Verify send resp", log.Dict{"result": res})
				return res, err
			}
		} else {
			res.Status = &jwt_pb.ResponseStatus{
				Status:  jwt_pb.ResponseStatus_FAILED,
				Message: "token verify error",
			}
			res.Payload = payloadb
			return res, err
		}
	}
}
