<?php

namespace JwtManager;

class JwtManager
{
    private $appSecret;
    private $algorithm = 'HS256';
    private $type = 'JWT';
    private $hash = 'sha256';
    private $context;
    private $expire;
    private $renew;

    /**
     * constructor
     * @param string $appSecret
     * @param string $context
     * @param int $expire
     * @param int $renew
     * @return void
     */
    public function __construct(
        string $appSecret,
        string $context,
        int $expire = 900,
        int $renew = 300
    ) {
        $this->appSecret = $appSecret;
        $this->context = $context;
        $this->expire = $expire;
        $this->renew = $renew;
    }

    /**
     * mount and get the header part
     * @return string
     */
    private function getHeader(): string
    {
        $header = [
            'alg' => $this->algorithm,
            'typ' => $this->type,
        ];
        $header = json_encode($header);
        return base64_encode($header);
    }

    /**
     * mount and get the payload part
     * @param string $audience
     * @param string $subject
     * @return string
     */
    private function getPayload(
        string $audience,
        string $subject
    ): string {
        $payload = [
            'aud' => $audience,
            'exp' => $this->expire,
            'iat' => time(date('Y-m-d H:i:s')),
            'iss' => $this->context,
            'sub' => $subject,
        ];
        $payload = json_encode($payload);
        return base64_encode($payload);
    }

    /**
     * mount and get the signature part
     * @param string $header
     * @param string $payload
     * @return string
     */
    private function getSignature(
        string $header,
        string $payload
    ): string {
        $signature = hash_hmac(
            $this->hash,
            $header . '.' . $payload,
            $this->appSecret . $this->context,
            true
        );
        return base64_encode($signature);
    }

    /**
     * split in parts a received token
     * @param string $token
     * @return array
     */
    private function splitParts(
        string $token
    ): array {
        $part = explode('.', $token);
        return [
            'header' => $part[0],
            'payload' => $part[1],
            'signature' => $part[2],
        ];
    }

    /**
     * actual expire time
     * @return int
     */
    public function getexpire(): int
    {
        return $this->expire;
    }

    /**
     * generate token
     * @param string $audience
     * @param string $subject
     * @return string
     */
    public function generate(
        string $audience,
        string $subject = ''
    ): string {
        $header = $this->getHeader();
        $payload = $this->getPayload($audience, $subject);
        $signature = $this->getSignature($header, $payload);

        return $header . '.' . $payload . '.' . $signature;
    }

    /**
     * check if is a valid token
     * @param string $token
     * @throws \Exception
     * @return bool
     */
    public function isValid(
        string $token
    ): bool {
        $correctFormat = preg_match('^([a-zA-Z0-9_=]{4,})\.([a-zA-Z0-9_=]{4,})\.([a-zA-Z0-9_\-\+\/=]{4,})^', $token);
        if (!$correctFormat) {
            throw new \Exception('Invalid JWT Token', 401);
        }

        $part = $this->splitParts($token);
        $valid = $this->getSignature($part['header'], $part['payload']);

        if ($part['signature'] !== $valid) {
            throw new \Exception('Invalid JWT Token', 401);
        }
        return true;
    }

    /**
     * check if token is on time
     * @param string $token
     * @throws \Exception
     * @return bool
     */
    public function isOnTime(
        string $token
    ): bool {
        $payload = $this->decodePayload($token);
        $iat = $payload['iat'] ?? null;
        $exp = $payload['exp'] ?? null;
        if (empty($iat) || empty($exp)) {
            throw new \Exception('Invalid JWT Token', 401);
        }

        $validUntil = date('Y-m-d H:i:s', $iat + $exp);
        $moment = date('Y-m-d H:i:s');
        if ($moment > $validUntil) {
            throw new \Exception('Expired JWT Token', 401);
        }
        return true;
    }

    /**
     * check if is need refresh token
     * @param string $token
     * @throws \Exception
     * @return bool
     */
    public function tokenNeedToRefresh(
        string $token
    ): bool {
        $payload = $this->decodePayload($token);
        $iat = $payload['iat'] ?? null;
        $exp = $payload['exp'] ?? null;
        if (empty($iat) || empty($exp)) {
            throw new \Exception('Invalid JWT Token', 401);
        }

        $almostExpired = date('Y-m-d H:i:s', $iat + $this->renew);
        $moment = date('Y-m-d H:i:s');
        if ($moment > $almostExpired) {
            return true;
        }
        return false;
    }

    /**
     * decode token payload
     * @param string $token
     * @return array
     */
    public function decodePayload(
        string $token
    ): array {
        $part = $this->splitParts($token);
        $payload = $part['payload'];

        $data = base64_decode($payload);
        return json_decode($data, true);
    }
}
