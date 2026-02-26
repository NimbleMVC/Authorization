<?php

use krzysztofzylka\DatabaseManager\AlterTable;
use krzysztofzylka\DatabaseManager\Column;
use krzysztofzylka\DatabaseManager\Enum\ColumnType;
use NimblePHP\Migrations\AbstractMigration;

return new class extends AbstractMigration {

    public function run(): void
    {
        $this->addOAuthColumnsToAccounts();
    }

    private function addOAuthColumnsToAccounts(): void
    {
        $alter = new AlterTable(\NimblePHP\Authorization\Config::$tableName);
        $alter->addColumn(Column::create('account_oauth_id', ColumnType::varchar, 255)->setNull(true));
        $alter->addColumn(Column::create('account_oauth_provider', ColumnType::varchar, 50)->setNull(true));
        $alter->execute();
    }
};
