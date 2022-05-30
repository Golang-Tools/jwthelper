package utils

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/Golang-Tools/jwthelper/v2/exceptions"
	"github.com/Golang-Tools/jwthelper/v2/jwt_pb"
)

//AlgoStrTOAlgoEnum 加密算法名转化为算法枚举值
func AlgoStrTOAlgoEnum(methodstr string) (jwt_pb.EncryptionAlgorithm, error) {
	switch strings.ToUpper(methodstr) {
	case "HS256":
		{
			return jwt_pb.EncryptionAlgorithm_HS256, nil
		}
	case "HS384":
		{
			return jwt_pb.EncryptionAlgorithm_HS384, nil
		}
	case "HS512":
		{
			return jwt_pb.EncryptionAlgorithm_HS512, nil
		}
	case "RS256":
		{
			return jwt_pb.EncryptionAlgorithm_RS256, nil
		}
	case "RS384":
		{
			return jwt_pb.EncryptionAlgorithm_RS384, nil
		}
	case "RS512":
		{
			return jwt_pb.EncryptionAlgorithm_RS512, nil
		}
	case "ES384":
		{
			return jwt_pb.EncryptionAlgorithm_ES384, nil
		}
	case "ES512":
		{
			return jwt_pb.EncryptionAlgorithm_ES512, nil
		}
	case "EdDSA":
		{
			return jwt_pb.EncryptionAlgorithm_EdDSA, nil
		}
	default:
		{
			return jwt_pb.EncryptionAlgorithm_UNKNOWN, exceptions.ErrAlgoType
		}
	}
}

//IsAsymmetric 算法在非对称加密支持的算法范围
func IsAsymmetric(method jwt_pb.EncryptionAlgorithm) bool {
	if method == jwt_pb.EncryptionAlgorithm_RS256 || method == jwt_pb.EncryptionAlgorithm_RS384 || method == jwt_pb.EncryptionAlgorithm_RS512 || method == jwt_pb.EncryptionAlgorithm_ES256 || method == jwt_pb.EncryptionAlgorithm_ES384 || method == jwt_pb.EncryptionAlgorithm_ES512 || method == jwt_pb.EncryptionAlgorithm_EdDSA {
		return true
	}
	return false
}

//IsSymmetric 算法在对称加密支持的算法范围
func IsSymmetric(method jwt_pb.EncryptionAlgorithm) bool {
	if method == jwt_pb.EncryptionAlgorithm_HS256 || method == jwt_pb.EncryptionAlgorithm_HS384 || method == jwt_pb.EncryptionAlgorithm_HS512 {
		return true
	}
	return false
}

// IsEs 判断文件是不是ES方法加密
func IsEs(method jwt_pb.EncryptionAlgorithm) bool {
	if method == jwt_pb.EncryptionAlgorithm_ES256 || method == jwt_pb.EncryptionAlgorithm_ES384 || method == jwt_pb.EncryptionAlgorithm_ES512 {
		return true
	} else {
		return false
	}
}

// IsRs 判断文件是不是RS方法加密
func IsRs(method jwt_pb.EncryptionAlgorithm) bool {
	if method == jwt_pb.EncryptionAlgorithm_RS256 || method == jwt_pb.EncryptionAlgorithm_RS384 || method == jwt_pb.EncryptionAlgorithm_RS512 {
		return true
	} else {
		return false
	}
}

// IsEdDSA 判断文件是不是EdDSA方法加密
func IsEdDSA(method jwt_pb.EncryptionAlgorithm) bool {
	if method == jwt_pb.EncryptionAlgorithm_EdDSA {
		return true
	} else {
		return false
	}
}

// // AsymmetricMethods 非对称加密支持的算法范围
// var CenterSupportedMethods = map[string]bool{
// 	"RS256": true,
// 	"HS256": true,
// }

// LoadData 读取并加载文件数据
func LoadData(p string) ([]byte, error) {
	if p == "" {
		return nil, fmt.Errorf("No path specified")
	}

	var rdr io.Reader
	if p == "-" {
		rdr = os.Stdin
	} else if p == "+" {
		return []byte("{}"), nil
	} else {
		if f, err := os.Open(p); err == nil {
			rdr = f
			defer f.Close()
		} else {
			return nil, err
		}
	}
	return ioutil.ReadAll(rdr)
}
