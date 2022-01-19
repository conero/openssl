package desp

import (
	"gitee.com/conero/uymas/str"
	"testing"
)

// AES-ECB			16/24
// AES-CBC			16/32
// 3DES-ECB			24
// DES-ECB			8
// DES-CBC			8
// 3DES-ECB			24
func TestAlgorithm_Encode_all(t *testing.T) {
	//秘钥长度：16/24/32
	// 随机密文
	bit := 24
	key := str.RandStr.SafeStr(bit)
	origin := str.RandStr.SafeStr(500) + "中华人民共和国-贵州.贵阳"

	for _, algStr := range algList {
		alg := NewAlgorithm(algStr, key)
		alg.Iv = str.RandStr.SafeStr(16)
		cp, err := alg.Encode(origin)
		if err != nil {
			t.Errorf("算法 %v 加密错误，%v", algStr, err)
			continue
		}

		// 解密参照
		refOrigin, er := alg.Decode(cp)
		if er != nil {
			t.Errorf("算法 %v 解密错误，%v", algStr, err)
			continue
		}

		if refOrigin != origin {
			t.Errorf("算法 %v 加解密错误，\n 秘钥 %v", algStr, key)
			continue
		}

		// 成功显示
		t.Logf("√ => 算法 %v 通过测试，加解密无误", algStr)
	}
}
