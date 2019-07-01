<?php

use \Mockery;
use JwtManager\JwtManager;

class JwtManagerTest extends PHPUnit\Framework\TestCase
{
    private $appSecret = 'DyONazNKD35e3TfpcOJGHewtjxPGkjSh';
    private $context = 'test';

    /**
     * @covers \src\JwtManager::__construct
     */
    public function testJwtManagerCanBeInstantiated()
    {
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $this->assertInstanceOf(JwtManager::class, $JwtManager);
    }

    /**
     * @covers \src\JwtManager::getExpire
     */
    public function testGetExpire()
    {
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $expire = $JwtManager->getExpire();
        
        $this->assertInstanceOf(JwtManager::class, $JwtManager);
        $this->assertInternalType('int', $expire);
    }

    /**
     * @covers \src\JwtManager::generate
     * @covers \src\JwtManager::getHeader
     * @covers \src\JwtManager::getPayload
     * @covers \src\JwtManager::getSignature
     */
    public function testGenerate()
    {
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $token = $JwtManager->generate('token', '68162dc1-a392-491f-9d46-639f0e0f179d');
        
        $this->assertInstanceOf(JwtManager::class, $JwtManager);
        $this->assertInternalType('string', $token);
        $this->assertRegExp('^([a-zA-Z0-9_=]{4,})\.([a-zA-Z0-9_=]{4,})\.([a-zA-Z0-9_\-\+\/=]{4,})^', $token);
    }

    /**
     * @covers \src\JwtManager::isValid
     * @covers \src\JwtManager::splitParts
     * @covers \src\JwtManager::getSignature
     */
    public function testIsValid()
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'.
            'eyJhdWQiOiJ0b2tlbiIsImV4cCI6OTAwLCJpYXQiOjE1NTk0MjY4MjksImlzcyI6InRlc'.
            '3QiLCJzdWIiOiI2ODE2MmRjMS1hMzkyLTQ5MWYtOWQ0Ni02MzlmMGUwZjE3OWQifQ==.'.
            '2QLo4djFNX4hm2FcNcGNRKkERgt26dEaqjhglpC2jPM=';
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $valid = $JwtManager->isValid($token);
        
        $this->assertInstanceOf(JwtManager::class, $JwtManager);
        $this->assertInternalType('boolean', $valid);
        $this->assertTrue($valid);
    }

    /**
     * @covers \src\JwtManager::isValid
     * @covers \src\JwtManager::splitParts
     * @covers \src\JwtManager::getSignature
     * @expectedException \Exception
     */
    public function testInvalidFormat()
    {
        $token = 'token';
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $valid = $JwtManager->isValid($token);
    }

    /**
     * @covers \src\JwtManager::isValid
     * @covers \src\JwtManager::splitParts
     * @covers \src\JwtManager::getSignature
     * @expectedException \Exception
     */
    public function testIsNotValid()
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'.
            '.eyJhdWQiOiJ0b2tlbiIsImV4cCI6MzAsImlhdCI6MTUzMjMwODY3MSwiaXNzIjoibXllZHV6ei1hcGkiLCJzdWIiOjgxNTk1OX0='.
            '.t5HzL1+FDvvi+T7JM8c9l12PM16R8CCj6lDKuCgwrong';
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $valid = $JwtManager->isValid($token);
    }

    /**
     * @covers \src\JwtManager::isOnTime
     * @covers \src\JwtManager::decodePayload
     */
    public function testIsOnTime()
    {
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $token = $JwtManager->generate('token', '68162dc1-a392-491f-9d46-639f0e0f179d');
        $onTime = $JwtManager->isOnTime($token);
        
        $this->assertInstanceOf(JwtManager::class, $JwtManager);
        $this->assertInternalType('boolean', $onTime);
        $this->assertTrue($onTime);
    }

    /**
     * @covers \src\JwtManager::isOnTime
     * @covers \src\JwtManager::decodePayload
     * @expectedException \Exception
     */
    public function testIsOnTimeMissingIatExp()
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'.
            '.eyJhdWQiOiJ0b2tlbiIsImlzcyI6Im15ZWR1enotYXBpIiwic3ViIjo4MTU5NTl9'.
            '.AkSOljnyMK4SM4bW5V04jiYClceFgINOrmcrqN4NsuQ=';
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $onTime = $JwtManager->isOnTime($token);
        
        $this->assertInstanceOf(JwtManager::class, $JwtManager);
        $this->assertInternalType('boolean', $onTime);
        $this->assertFalse($onTime);
    }

    /**
     * @covers \src\JwtManager::isOnTime
     * @covers \src\JwtManager::decodePayload
     * @covers \src\JwtManager::splitParts
     * @expectedException \Exception
     */
    public function testIsNotOnTime()
    {
        $oldToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'.
            '.eyJhdWQiOiJ0b2tlbiIsImV4cCI6MzAsImlhdCI6MTUzMjMwODY3MSwiaXNzIjoibXllZHV6ei1hcGkiLCJzdWIiOjgxNTk1OX0='.
            '.t5HzL1+FDvvi+T7JM8c9l12PM16R8CCj6lDKuCgDzHk=';
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $onTime = $JwtManager->isOnTime($oldToken);
    }

    /**
     * @covers \src\JwtManager::tokenNeedToRefresh
     * @covers \src\JwtManager::decodePayload
     * @covers \src\JwtManager::splitParts
     */
    public function testTokenNeedToRefresh()
    {
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context,
            2,
            1
        );
        $token = $JwtManager->generate('token', '68162dc1-a392-491f-9d46-639f0e0f179d');
        sleep(2);
        $need = $JwtManager->tokenNeedToRefresh($token);
        
        $this->assertInstanceOf(JwtManager::class, $JwtManager);
        $this->assertInternalType('boolean', $need);
        $this->assertTrue($need);
    }

    /**
     * @covers \src\JwtManager::tokenNeedToRefresh
     * @covers \src\JwtManager::decodePayload
     * @covers \src\JwtManager::splitParts
     * @expectedException \Exception
     */
    public function testTokenNeedToRefreshMissingIatExp()
    {
        $token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'.
            '.eyJhdWQiOiJ0b2tlbiIsImlzcyI6Im15ZWR1enotYXBpIiwic3ViIjo4MTU5NTl9'.
            '.AkSOljnyMK4SM4bW5V04jiYClceFgINOrmcrqN4NsuQ=';
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $need = $JwtManager->tokenNeedToRefresh($token);
        
        $this->assertInstanceOf(JwtManager::class, $JwtManager);
        $this->assertInternalType('boolean', $need);
        $this->assertTrue($need);
    }

    /**
     * @covers \src\JwtManager::tokenNeedToRefresh
     * @covers \src\JwtManager::decodePayload
     * @covers \src\JwtManager::splitParts
     */
    public function testTokenNotNeedToRefresh()
    {
        $JwtManager = new JwtManager(
            $this->appSecret,
            $this->context
        );
        $token = $JwtManager->generate('token', '68162dc1-a392-491f-9d46-639f0e0f179d');
        $need = $JwtManager->tokenNeedToRefresh($token);
        
        $this->assertInstanceOf(JwtManager::class, $JwtManager);
        $this->assertInternalType('boolean', $need);
        $this->assertFalse($need);
    }

    public function tearDown()
    {
        Mockery::close();
    }
}
