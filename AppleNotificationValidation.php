trait AppleNotificationValidation {
public function verifySignature($jws)
    {
        $data = explode(".", $jws);

        //getting header from cert
        $certs = json_decode(base64_decode($data[0]))->x5c;

        //validate that each certificate is issued and by next one in chain
        $chain_validation = true;
        for ($i = 0; $i < count($certs) - 1; $i++) {
            $x509 = new X509();
            $x509->loadX509($certs[$i]);
            $x509->loadCA($certs[$i + 1]);
            $chain_validation &= $x509->validateSignature() & $x509->validateDate();
        }


        //verify fingerprint that equal to G3 Apple Certificate fingerprint that we can get from apple PKI certificates
        $cert_resource = openssl_x509_read("-----BEGIN CERTIFICATE-----\n" . $certs[count($certs) - 1] . "\n-----END CERTIFICATE-----");
        $certificateFingerprint = openssl_x509_fingerprint($cert_resource, 'sha256', true);
        $fingerprintString = strtoupper(implode(':', str_split(bin2hex($certificateFingerprint), 2)));
        $chain_validation &= ($fingerprintString === self::APPLE_ROOT_CA_G3_FINGERPRINT);


        //validate jws signature base on public key that we fetched from first certificate

        //read public key
        $jwk = JWKFactory::createFromCertificate(
            "-----BEGIN CERTIFICATE-----\n" . $certs[0] . "\n-----END CERTIFICATE-----",
            ['use' => 'sig']
        );

        //deserialize jws certificate
        $jws = (new CompactSerializer())->unserialize($jws);

        $algorithmManager = new AlgorithmManager([new ES256()]);
        $chain_validation &= (new JWSVerifier($algorithmManager))->verifyWithKey($jws, $jwk, 0);

        if (!$chain_validation)
            throw new CustomException("certificate validation failed", 400);
    }
}
