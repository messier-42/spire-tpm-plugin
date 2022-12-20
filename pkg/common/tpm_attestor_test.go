package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecode(t *testing.T) {
	testCases := []struct {
		name     string
		hasCert  bool
		pemBytes []byte
		pubHash  string
	}{
		{
			name:    "certificate",
			hasCert: true,
			pemBytes: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2yOjFnHabN1HIOqGYQgQ
2YsUdsqXh86VlVTq8K8MgYuq+W3GmapDiixybQYcyvO9oYDUx7qVnwWQ/ieTaRwj
+rD2GoI+F1OqKW/7KFEPpBUbef4sYqcAf8PYYrRhcti9xVo9gYUXtrLw7oGGaMOd
KPFhqDy8X9/HEuBp8txcMjVFEw0VzCI7w26hx5FbkUI+ZVay2CUj8vXb0ezyJEi8
Fpx/oAru93wQx5j2Hk3hmcBiCt8/Lk3EOLGjxtqtKvRz6yyD6rcqLQdFjVT2LDDN
UIoZGdOPsKup4A4wswjNJkq6571ehL5bHKP+dgtYkwm6rqAopVBrBQv2fUFsJPOt
bQIDAQAB
-----END PUBLIC KEY-----
-----BEGIN CERTIFICATE-----
MIIDUjCCAvegAwIBAgILAPgAb/qKrKImI80wCgYIKoZIzj0EAwIwVTFTMB8GA1UE
AxMYTnV2b3RvbiBUUE0gUm9vdCBDQSAyMTExMCUGA1UEChMeTnV2b3RvbiBUZWNo
bm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwHhcNMjExMTA3MDY0MjUxWhcN
NDExMTAzMDY0MjUxWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
2yOjFnHabN1HIOqGYQgQ2YsUdsqXh86VlVTq8K8MgYuq+W3GmapDiixybQYcyvO9
oYDUx7qVnwWQ/ieTaRwj+rD2GoI+F1OqKW/7KFEPpBUbef4sYqcAf8PYYrRhcti9
xVo9gYUXtrLw7oGGaMOdKPFhqDy8X9/HEuBp8txcMjVFEw0VzCI7w26hx5FbkUI+
ZVay2CUj8vXb0ezyJEi8Fpx/oAru93wQx5j2Hk3hmcBiCt8/Lk3EOLGjxtqtKvRz
6yyD6rcqLQdFjVT2LDDNUIoZGdOPsKup4A4wswjNJkq6571ehL5bHKP+dgtYkwm6
rqAopVBrBQv2fUFsJPOtbQIDAQABo4IBNjCCATIwUAYDVR0RAQH/BEYwRKRCMEAx
PjAUBgVngQUCARMLaWQ6NEU1NDQzMDAwEAYFZ4EFAgITB05QQ1Q3NXgwFAYFZ4EF
AgMTC2lkOjAwMDcwMDAyMAwGA1UdEwEB/wQCMAAwEAYDVR0lBAkwBwYFZ4EFCAEw
HwYDVR0jBBgwFoAUI/TiKtO+N0pEl3KVSqKDrtdSVy4wDgYDVR0PAQH/BAQDAgUg
MCIGA1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgCKMGkGCCsGAQUFBwEB
BF0wWzBZBggrBgEFBQcwAoZNaHR0cHM6Ly93d3cubnV2b3Rvbi5jb20vc2VjdXJp
dHkvTlRDLVRQTS1FSy1DZXJ0L051dm90b24gVFBNIFJvb3QgQ0EgMjExMS5jZXIw
CgYIKoZIzj0EAwIDSQAwRgIhAK8SmYWQUDCxLkCYLmTVEzkqPQk7Ioq+UoTEF65y
qw5EAiEA2J6Hy0GV4Psh9nEV+51jxYS10PE+xvib03KA+xVBJxM=
-----END CERTIFICATE-----`),
			pubHash: "5f4f4e37a35ed4d11ae72587e5f0c87b3ce784fa372767f9f986b0b7bf29a328",
		},
		{
			name: "ec public key",
			pemBytes: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7mnx2ikpijr+7wbh/S67NKPeU7yE
6IDPKOOrt7W15Xs+O2aW2xMNKCCaC2QAMnDuXKogKnOr7Ri0firFrSlGIg==
-----END PUBLIC KEY-----`),
			pubHash: "d6c53c09ab792f1ea72d2ed52d7c9e587b1934489f7cde87d716e03f9fbda770",
		},
		{
			name: "rsa public key",
			pemBytes: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0SizQMxTx/8xN1IW2Nld
r5CcQVo9nk6p3fkkCIgzC1HsNX953LAKU5Xz1aSGxFQGtO7+hhMH++3qEtxgpntA
97pDfum4Rd1OUTGy+rHFrKNehBn/M9vfXeToDS5UuOr93tBR7KRJ7sW724GGAJAK
AGSfS3GLIpvcJ+gvzQoD76ox1d4bnLBXCAxAfuj3qYaeaNr4M5OKVOYNWk4dU+8U
ULm2HTqoNWSLkKqTaOn4VpQ2isFpDRpiBNq5N5mafaPWHeZixz2HAkajN94kAuk3
zopyzROwOXvNxRe6ttycHP34Hh7cRZAelyyJH5qrTQe/p+W1G5ssuWLd3Z1/qbbO
ZQIDAQAB
-----END PUBLIC KEY-----`),
			pubHash: "4d529cb0f819fd7d6fe8cd7d3fbc1a67178ae1e86c44cdc73e651646bc1517c9",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require := require.New(t)

			pemBytes := testCase.pemBytes

			for i := 0; i < 3; i++ {
				ek, err := DecodeEK(pemBytes)
				require.NoError(err)
				if testCase.hasCert {
					require.NotNil(ek.Certificate)
				}

				pubHash, err := GetPubHash(ek)
				require.NoError(err)
				require.Equal(testCase.pubHash, pubHash)

				pemBytes, err = EncodeEK(ek)
				require.NoError(err)
			}
		})
	}
}
