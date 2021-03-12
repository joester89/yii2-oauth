<?php

namespace WolfpackIT\oauth\components\repository;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use WolfpackIT\oauth\components\Repository;
use WolfpackIT\oauth\interfaces\ClientEntityInterface;
use WolfpackIT\oauth\models\activeRecord\Client;
use yii\base\InvalidConfigException;
use yii\db\ActiveQuery;

/**
 * Class ClientRepository
 * @package WolfpackIT\oauth\components\repository
 */
class ClientRepository
    extends Repository
    implements ClientRepositoryInterface
{
    /**
     * @var string
     */
    public $modelClass = Client::class;

    /**
     * @param string $clientIdentifier
     * @param null $grantType
     * @param null $clientSecret
     * @param bool $mustValidateSecret
     * @return Client|null
     */
    public function getClientEntity(
        $clientIdentifier
    ): ?Client {
        return $this->modelClass::find()
            ->active()
            ->notDeleted()
            ->andWhere(['identifier' => $clientIdentifier])
            ->one()
        ;
    }

    public function init()
    {
        if (!is_subclass_of($this->modelClass, ClientEntityInterface::class)) {
            throw new InvalidConfigException('Model class must implement ' . ClientEntityInterface::class);
        }

        parent::init();
    }

    /**
     * @param string $clientIdentifier
     * @param null|string $clientSecret
     * @param null|string $grantType
     * @return bool
     */
    public function validateClient($clientIdentifier, $clientSecret, $grantType): bool
    {
        $client = $this->getClientEntity($clientIdentifier);

        if (
            !$client
            || !$client->getClientGrantTypes()->andWhere(['grant_type' => $grantType])->exists()
        ) {
            return false;
        }


        if ($client->isConfidential()) {
            return $client->secretVerify($clientSecret);
        }

        return true;
    }
}
