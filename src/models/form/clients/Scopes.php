<?php

namespace oauth\models\form\clients;

use oauth\models\activeRecord\Client;
use oauth\models\activeRecord\ClientScope;
use oauth\models\activeRecord\Scope;
use oauth\models\Form;
use yii\helpers\ArrayHelper;
use yii\validators\DefaultValueValidator;
use yii\validators\RangeValidator;

/**
 * Class Scopes
 * @package oauth\models\form
 */
class Scopes extends Form
{
    public $scopes = [];

    private $client;
    private $_setScopes;

    /**
     * Scopes constructor.
     * @param Client $client
     * @param array $config
     */
    public function __construct(Client $client, array $config = [])
    {
        $this->client = $client;
        $this->scopes = $this->_setScopes = ArrayHelper::getColumn($client->clientScopes, 'id');
        parent::__construct($config);
    }

    /**
     * @return array
     */
    public function attributeLabels(): array
    {
        return [
            'scopes' => \Yii::t('app', 'Scopes'),
        ];
    }

    /**
     * @return array
     */
    public function rules()
    {
        return [
            [['scopes'], RangeValidator::class, 'range' => array_keys($this->scopeOptions()), 'allowArray' => true],
            [['scopes'], DefaultValueValidator::class, 'value' => []]
        ];
    }

    /**
     * @return bool
     * @throws \yii\db\Exception
     */
    public function runInternal(): bool
    {
        if($result = $this->validate()) {
            $transaction = $this->client::getDb()->beginTransaction();
            $transactionLevel = $transaction->level;

            try {
                //Remove unselected scopes
                $scopesToRemove = array_diff($this->_setScopes, $this->scopes);
                if (!empty($scopesToRemove)) {
                    $result &= 0 < ClientScope::deleteAll(
                        ['client_id' => $this->client->id, 'scope_id' => $scopesToRemove]
                    );
                }

                //Add added scopes
                $scopesToAdd = array_diff($this->scopes, $this->_setScopes);
                foreach ($scopesToAdd as $scopeToAdd) {
                    $clientScope = new ClientScope([
                        'client_id' => $this->client->id,
                        'scope_id' => $scopeToAdd
                    ]);
                    $result &= $clientScope->save();
                }

                if ($result) {
                    $transaction->commit();
                }
            } finally {
                if ($transaction->isActive && $transaction->level === $transactionLevel) {
                    $transaction->rollBack();
                }
            }
        }

        return $result;
    }

    public function scopeOptions(): array
    {
        return ArrayHelper::map(
            Scope::find()->select(['id', 'name'])->asArray()->all(),
            'id',
            'name'
        );
    }
}