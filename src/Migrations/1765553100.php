<?php

use krzysztofzylka\DatabaseManager\Column;
use krzysztofzylka\DatabaseManager\CreateTable;
use krzysztofzylka\DatabaseManager\Enum\ColumnType;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Migrations\AbstractMigration;

return new class extends AbstractMigration {

    public function run(): void
    {
        $this->createTokenBlacklistTable();
        $this->createAPIKeysTable();
        $this->createAPIKeyUsageTable();
    }

    private function createTokenBlacklistTable(): void
    {
        $table = new Table('account_token_blacklist');

        if ($table->exists()) {
            return;
        }

        $create = new CreateTable('account_token_blacklist');
        $create->addIdColumn();
        $create->addSimpleVarcharColumn('token_jti');
        $create->addSimpleVarcharColumn('token_type', 50);
        $create->addColumn(Column::create('revoked_at', ColumnType::datetime, null));
        $create->addDateModifyColumn();
        $create->addDateCreatedColumn();
        $create->execute();
    }

    private function createAPIKeysTable(): void
    {
        $table = new Table('account_api_keys');
        
        if ($table->exists()) {
            return;
        }

        $create = new CreateTable('account_api_keys');
        $create->addIdColumn();
        $create->addcolumn(Column::create('user_id', ColumnType::bigint, null)->setUnsigned(true));
        $create->addSimpleVarcharColumn('key_hash', 64, false);
        $create->addSimpleVarcharColumn('key_name', 255);
        $create->addSimpleTextColumn('scopes');
        $create->addsimpleintColumn('rate_limit', 1000);
        $create->addDateModifyColumn('created_at');
        $create->addcolumn(Column::create('revoked_at', ColumnType::datetime, null));
        $create->addcolumn(Column::create('expires_at', ColumnType::datetime, null));
        $create->addcolumn(Column::create('last_used_at', ColumnType::datetime, null));
        $create->addSimpleBoolColumn('is_active', 1);
        $create->addDateModifyColumn();
        $create->addDateCreatedColumn();
        $create->execute();
    }

    private function createAPIKeyUsageTable(): void
    {
        $table = new Table('account_api_key_usage');
        
        if ($table->exists()) {
            return;
        }

        $create = new CreateTable('account_api_key_usage');
        $create->addIdColumn();
        $create->addcolumn(Column::create('user_id', ColumnType::bigint, null)->setUnsigned(true));
        $create->addSimpleVarcharColumn('key_hash', 64, false);
        $create->addSimpleVarcharColumn('ip_address', 45);
        $create->addSimpleTextColumn('user_agent', null);
        $create->addcolumn(Column::create('accessed_at', ColumnType::datetime, null));
        $create->addSimpleBoolColumn('is_active', 1);
        $create->addDateModifyColumn();
        $create->addDateCreatedColumn();
        $create->execute();
    }
};
