<?php

namespace WolfpackIT\oauth\components;

use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\ValidationData;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use WolfpackIT\oauth\components\repository\AccessTokenRepository;
use WolfpackIT\oauth\Module;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\di\Instance;
use yii\web\Request;
use yii\web\UnauthorizedHttpException;

/**
 * Class AccessTokenService
 * @package WolfpackIT\oauth\components
 */
class AccessTokenService extends Component
{
    /**
     * @var string|array|AccessTokenRepositoryInterface
     */
    public $accessTokenRepository = AccessTokenRepository::class;

    /**
     * @var CryptKey
     */
    public $publicKey;

    /**
     * @var string
     */
    public $tokenHeader = 'Authorization';

    /**
     * @var string
     */
    public $tokenPattern = '/^Bearer\s+(.*?)$/';

    /**
     * @throws InvalidConfigException
     */
    public function init()
    {
        $this->accessTokenRepository = is_string($this->accessTokenRepository) && \Yii::$app->has($this->accessTokenRepository)
            ? \Yii::$app->get($this->accessTokenRepository)
            : \Yii::createObject($this->accessTokenRepository);

        if (!$this->accessTokenRepository instanceof AccessTokenRepositoryInterface) {
            throw new InvalidConfigException('Access token repository must be instance of ' . AccessTokenRepositoryInterface::class);
        }

        if (!isset($this->tokenHeader, $this->tokenPattern)) {
            throw new InvalidConfigException('TokenHeader and TokenPattern must be set.');
        }

        $this->publicKey = $this->publicKey ?? Module::getInstance()->publicKey;
        Instance::ensure($this->publicKey, CryptKey::class);

        parent::init();
    }

    /**
     * @param Request $request
     * @return string|null
     */
    public function getJwtFromRequest(Request $request): ?string
    {
        $authHeader = $request->getHeaders()->get($this->tokenHeader);

        if (is_null($authHeader)) {
            return null;
        }

        if (preg_match($this->tokenPattern, $authHeader, $matches)) {
            return $matches[1];
        } else {
            return null;
        }
    }

    /**
     * @param $jwt
     * @return Token|null
     * @throws InvalidConfigException
     */
    public function getToken($jwt): ?Token
    {
        $result = null;

        try {
            $result = $this->getAndValidateToken($jwt);
        } catch (UnauthorizedHttpException $e) {
            $result = null;
        }

        return $result;
    }

    /**
     * @param $jwt
     * @return Token
     * @throws InvalidConfigException
     * @throws UnauthorizedHttpException
     */
    public function getAndValidateToken($jwt): Token
    {
        try {
            $configuration = Configuration::forAsymmetricSigner(
                new Sha256(),
                InMemory::plainText(''),
                LocalFileReference::file($this->publicKey->getKeyPath())
            );

            try {
                $token = $configuration->parser()->parse($jwt);
            } catch (CannotDecodeContent | Token\InvalidTokenStructure | Token\UnsupportedHeaderFound $e) {
                throw new UnauthorizedHttpException('Failed parsing access token with message: ' . $exception->getMessage(), 0, $e);
            }

            $constraints = [
                new StrictValidAt(SystemClock::fromSystemTimezone()),
            ];

            try {
                $configuration->validator()->assert($token, ...$constraints);
            } catch (RequiredConstraintsViolated $e) {
                throw new UnauthorizedHttpException('Access token is invalid', 0, $e);
            }

            if ($this->accessTokenRepository->isAccessTokenRevoked($token->claims()->get('jti'))) {
                throw new UnauthorizedHttpException('Access token has been revoked');
            }

            return $token;
        } catch (\InvalidArgumentException $exception) {
            // JWT couldn't be parsed so return the request as is
            throw new UnauthorizedHttpException($exception->getMessage());
        }
    }
}
