const crypto = require('crypto');

function signature(message) {
    const sign = crypto.createSign('RSA-SHA256');
    //INSECURE key just for testing!
const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgFq0Dl89MtCdZeC48iDZHPXrvl34zGc6gYQD1ELRwp/2a9NbSDLn
cktRMeVAJXDP+fktzBlIwVZF+vfSxn/Bti1sTnNhZQ5T6JUB2ZK6GIn+Kk7cXJKP
J3q39gdp5BFW0o12CmjLBgg2Nd5ZVwm0LgOdkVwvnwpqkxg9k+4YrVgLAgMBAAEC
gYA9ejUTkGNUypo2yqQyZ3YdqP+KqgvBHAKU/BNuhsYnrdo/k2tINV9edVYgUG4Q
HKcNoWDo8ks4so38Uzx/c0iKinG5nQPxGvq0yfjAiH4S1YOwMUlTBHOzbyARkAlY
7Up+/ayVldHahCzc+t0CeW+ymwftlKpIY+oUPLsY4n0qAQJBAJwednNmHoHuD5Iv
+qpFQfHTsfHB2eLPO/7aByTRo/DePTSVXVAH89xsFsJhjvt5cPqbv3UM4Q98drs7
EwnjFEECQQCUu6nygVVlhE71c4tIkOTDPy59DJ93ZmxOFCLZJUdkacPo9d4Ta4gc
DoQdtqFMLxMSAzuavGk43S7IaHP66ClLAkBcM31/P9NKpv8ZNi7TOp3spTrVbcgx
tHRZWgiYDRvGWGpLUN9QMbIq/sceO6HHEPzRdQRIq7eLftVcVFI1J6BBAkAqSWTb
PuxRrZlpbc1290MjQ+5qvVEFeIhodo8l39R5dxytOmJGcTdEitgDPq6DY4rvfx3O
M61S7ofjkNcQyjsbAkBAnH++dFPMZ0v26B7FVVwUbWD5bMJtlfQXEh3B5OcjY4J9
D/zBoCAIVwfj+cw9HvtX/C4uOBCI/Zya0A2G+9Nu
-----END RSA PRIVATE KEY-----   `;
const publicKey = `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFq0Dl89MtCdZeC48iDZHPXrvl34
zGc6gYQD1ELRwp/2a9NbSDLncktRMeVAJXDP+fktzBlIwVZF+vfSxn/Bti1sTnNh
ZQ5T6JUB2ZK6GIn+Kk7cXJKPJ3q39gdp5BFW0o12CmjLBgg2Nd5ZVwm0LgOdkVwv
nwpqkxg9k+4YrVgLAgMBAAE=
-----END PUBLIC KEY-----`;
sign.write(message);
sign.end();
return sign.sign(privateKey, 'hex');
}

module.exports = signature;