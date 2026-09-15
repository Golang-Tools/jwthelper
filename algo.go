// 算法的解析与分类。
package jwthelper

import (
	"strings"

	"github.com/Golang-Tools/jwthelper/v4/exceptions"
)

// ParseAlgo 将算法名解析为Algo,名字大小写不敏感
func ParseAlgo(methodstr string) (Algo, error) {
	switch strings.ToUpper(methodstr) {
	case "HS256":
		{
			return AlgoHS256, nil
		}
	case "HS384":
		{
			return AlgoHS384, nil
		}
	case "HS512":
		{
			return AlgoHS512, nil
		}
	case "RS256":
		{
			return AlgoRS256, nil
		}
	case "RS384":
		{
			return AlgoRS384, nil
		}
	case "RS512":
		{
			return AlgoRS512, nil
		}
	case "ES256":
		{
			return AlgoES256, nil
		}
	case "ES384":
		{
			return AlgoES384, nil
		}
	case "ES512":
		{
			return AlgoES512, nil
		}
	case "EDDSA":
		{
			return AlgoEdDSA, nil
		}
	default:
		{
			return "", exceptions.ErrAlgoType
		}
	}
}

// IsAsymmetric 算法属于非对称加密支持的算法范围
func IsAsymmetric(method Algo) bool {
	if method == AlgoRS256 || method == AlgoRS384 || method == AlgoRS512 || method == AlgoES256 || method == AlgoES384 || method == AlgoES512 || method == AlgoEdDSA {
		return true
	}
	return false
}

// IsSymmetric 算法属于对称加密支持的算法范围
func IsSymmetric(method Algo) bool {
	if method == AlgoHS256 || method == AlgoHS384 || method == AlgoHS512 {
		return true
	}
	return false
}

// IsEs 判断算法是不是ES方法加密
func IsEs(method Algo) bool {
	if method == AlgoES256 || method == AlgoES384 || method == AlgoES512 {
		return true
	}
	return false
}

// IsRs 判断算法是不是RS方法加密
func IsRs(method Algo) bool {
	if method == AlgoRS256 || method == AlgoRS384 || method == AlgoRS512 {
		return true
	}
	return false
}

// IsEdDSA 判断算法是不是EdDSA方法加密
func IsEdDSA(method Algo) bool {
	if method == AlgoEdDSA {
		return true
	}
	return false
}
