package verifierserv

import (
	"context"
	"encoding/json"

	"github.com/Golang-Tools/jwthelper/contrib/pb/jwtpb"
	"github.com/Golang-Tools/jwthelper/contrib/pb/pbconv"
	"github.com/Golang-Tools/jwthelper/contrib/pb/verifierpb"
	"github.com/Golang-Tools/jwthelper/v4/exceptions"
	"github.com/Golang-Tools/jwthelper/v4/verifyoptions"
	log "github.com/Golang-Tools/loggerhelper/v4"
	"github.com/Golang-Tools/optparams"
)

// Meta 查看签名器的元信息
func (s *Server) Meta(ctx context.Context, in *verifierpb.MetaRequest) (*verifierpb.MetaResponse, error) {
	log.Debug("Meta get message", log.Dict{"in": in})
	meta, err := s.verifier.Meta(ctx)
	if err != nil {
		return nil, err
	}
	res := &verifierpb.MetaResponse{
		Status: &jwtpb.ResponseStatus{
			Status: jwtpb.ResponseStatus_SUCCEED,
		},
		Data: pbconv.VerifierMetaToPB(meta),
	}
	log.Debug("Meta send resp", log.Dict{"result": res})
	return res, nil
}

// Verify 校验签名
func (s *Server) Verify(ctx context.Context, in *verifierpb.VerifyRequest) (*verifierpb.VerifyResponse, error) {
	res := &verifierpb.VerifyResponse{}
	log.Debug("Sign get message", log.Dict{"in": in})
	opts := []optparams.Option[verifyoptions.VerifyOptions]{}
	if in.CheckMatchSub != "" {
		opts = append(opts, verifyoptions.WithSUBMustBe(in.CheckMatchSub))
	}
	if in.CheckMatchallAud != nil && len(in.CheckMatchallAud) > 0 {
		opts = append(opts, verifyoptions.WithAUDMustHas(in.CheckMatchallAud...))
	}
	if in.CheckMatchanyAud != nil && len(in.CheckMatchanyAud) > 0 {
		opts = append(opts, verifyoptions.WithAUDMustHasAny(in.CheckMatchanyAud...))
	}
	if in.CheckNotmatchAud != nil && len(in.CheckNotmatchAud) > 0 {
		opts = append(opts, verifyoptions.WithAUDMustNotHas(in.CheckNotmatchAud...))
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
	status, err := s.verifier.Verify(ctx, pbconv.TokenFromPB(in.Token), &payload, opts...)
	payloadb, err1 := json.Marshal(payload)
	if err1 != nil {
		res.Status = &jwtpb.ResponseStatus{
			Status:    jwtpb.ResponseStatus_FAILED,
			Message:   "get payload error",
			ErrorKind: exceptions.KindOf(err1),
		}
		return res, nil
	}
	if err == nil {
		res.Status = &jwtpb.ResponseStatus{
			Status: jwtpb.ResponseStatus_SUCCEED,
		}
		res.JwtStatus = pbconv.JwtStatusToPB(status)
		res.Payload = payloadb
		log.Debug("Verify send resp", log.Dict{"result": res})
		return res, nil
	} else {
		if err == exceptions.ErrValidationErrorExpired {
			if status != nil {
				res.Status = &jwtpb.ResponseStatus{
					Status:    jwtpb.ResponseStatus_SUCCEED,
					ErrorKind: exceptions.KindOf(err),
				}
				res.JwtStatus = pbconv.JwtStatusToPB(status)
				res.Payload = payloadb
				log.Debug("Verify send resp", log.Dict{"result": res})
				return res, nil
			} else {
				res.Status = &jwtpb.ResponseStatus{
					Status:    jwtpb.ResponseStatus_FAILED,
					Message:   "olny access token and is expored",
					ErrorKind: exceptions.KindOf(err),
				}
				res.Payload = payloadb
				log.Debug("Verify send resp", log.Dict{"result": res})
				return res, nil
			}
		} else {
			res.Status = &jwtpb.ResponseStatus{
				Status:    jwtpb.ResponseStatus_FAILED,
				Message:   "token verify error",
				ErrorKind: exceptions.KindOf(err),
			}
			res.Payload = payloadb
			return res, nil
		}
	}
}
