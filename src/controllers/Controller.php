<?php

namespace WolfpackIT\oauth\controllers;

use SamIT\Yii2\Traits\ActionInjectionTrait;
use yii\web\Controller as YiiController;

/**
 * Class Controller
 * @package WolfpackIT\oauth\controllers
 */
abstract class Controller extends YiiController
{
    use ActionInjectionTrait;
}