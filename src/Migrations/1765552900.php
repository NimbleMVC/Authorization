<?php

use krzysztofzylka\DatabaseManager\AlterTable;
use krzysztofzylka\DatabaseManager\Column;
use krzysztofzylka\DatabaseManager\Enum\ColumnType;
use NimblePHP\Migrations\AbstractMigration;

return new class extends AbstractMigration {

    public function run(): void
    {
        $this->addTwoFactorColumnsToAccounts();
    }

    private function addTwoFactorColumnsToAccounts(): void
    {
        $alter = new AlterTable(\NimblePHP\Authorization\Config::$tableName);

        $secretColumn = new Column();
        $secretColumn->setName('account_two_factor_secret');
        $secretColumn->setType(ColumnType::varchar, 255);
        $secretColumn->setNull(true);
        $alter->addColumn($secretColumn);

        $providerColumn = new Column();
        $providerColumn->setName('account_two_factor_provider');
        $providerColumn->setType(ColumnType::varchar, 50);
        $providerColumn->setNull(true);
        $alter->addColumn($providerColumn);

        $alter->execute();
    }
};
