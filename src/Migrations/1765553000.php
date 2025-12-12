<?php

use krzysztofzylka\DatabaseManager\AlterTable;
use krzysztofzylka\DatabaseManager\Column;
use krzysztofzylka\DatabaseManager\Enum\ColumnType;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Migrations\AbstractMigration;

return new class extends AbstractMigration {

    public function run(): void
    {
        $this->addOAuthColumnsToAccounts();
    }

    private function addOAuthColumnsToAccounts(): void
    {
        $table = new Table('accounts');

        $alter = new AlterTable('accounts');

        $oauthIdColumn = new Column();
        $oauthIdColumn->setName('account_oauth_id');
        $oauthIdColumn->setType(ColumnType::varchar, 255);
        $oauthIdColumn->setNull(true);
        $alter->addColumn($oauthIdColumn);

        $oauthProviderColumn = new Column();
        $oauthProviderColumn->setName('account_oauth_provider');
        $oauthProviderColumn->setType(ColumnType::varchar, 50);
        $oauthProviderColumn->setNull(true);
        $alter->addColumn($oauthProviderColumn);

        $alter->execute();
    }
};
