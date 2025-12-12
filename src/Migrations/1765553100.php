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

        $id = new Column();
        $id->setName('id');
        $id->setType(ColumnType::int);
        $id->setAutoIncrement(true);
        $id->setPrimary(true);
        $create->addColumn($id);

        $jti = new Column();
        $jti->setName('token_jti');
        $jti->setType(ColumnType::varchar, 255);
        $jti->setNull(false);
        $create->addColumn($jti);

        $type = new Column();
        $type->setName('token_type');
        $type->setType(ColumnType::varchar, 50);
        $type->setNull(false);
        $create->addColumn($type);

        $revoked = new Column();
        $revoked->setName('revoked_at');
        $revoked->setType(ColumnType::datetime);
        $create->addColumn($revoked);

        $create->execute();
    }

    private function createAPIKeysTable(): void
    {
        $table = new Table('account_api_keys');
        
        if ($table->exists()) {
            return;
        }

        $create = new CreateTable('account_api_keys');

        $id = new Column();
        $id->setName('id');
        $id->setType(ColumnType::int);
        $id->setAutoIncrement(true);
        $id->setPrimary(true);
        $create->addColumn($id);

        $userId = new Column();
        $userId->setName('user_id');
        $userId->setType(ColumnType::int);
        $userId->setNull(false);
        $create->addColumn($userId);

        $hash = new Column();
        $hash->setName('key_hash');
        $hash->setType(ColumnType::varchar, 64);
        $hash->setNull(false);
        $create->addColumn($hash);

        $name = new Column();
        $name->setName('key_name');
        $name->setType(ColumnType::varchar, 255);
        $create->addColumn($name);

        $scopes = new Column();
        $scopes->setName('scopes');
        $scopes->setType(ColumnType::text);
        $scopes->setNull(true);
        $create->addColumn($scopes);

        $limit = new Column();
        $limit->setName('rate_limit');
        $limit->setType(ColumnType::int);
        $limit->setDefault(1000);
        $create->addColumn($limit);

        $created = new Column();
        $created->setName('created_at');
        $created->setType(ColumnType::datetime);
        $create->addColumn($created);

        $expires = new Column();
        $expires->setName('expires_at');
        $expires->setType(ColumnType::datetime);
        $expires->setNull(true);
        $create->addColumn($expires);

        $lastUsed = new Column();
        $lastUsed->setName('last_used_at');
        $lastUsed->setType(ColumnType::datetime);
        $lastUsed->setNull(true);
        $create->addColumn($lastUsed);

        $active = new Column();
        $active->setName('is_active');
        $active->setType(ColumnType::tinyint);
        $active->setDefault(1);
        $create->addColumn($active);

        $create->execute();
    }

    private function createAPIKeyUsageTable(): void
    {
        $table = new Table('account_api_key_usage');
        
        if ($table->exists()) {
            return;
        }

        $create = new CreateTable('account_api_key_usage');

        $id = new Column();
        $id->setName('id');
        $id->setType(ColumnType::int);
        $id->setAutoIncrement(true);
        $id->setPrimary(true);
        $create->addColumn($id);

        $hash = new Column();
        $hash->setName('key_hash');
        $hash->setType(ColumnType::varchar, 64);
        $create->addColumn($hash);

        $userId = new Column();
        $userId->setName('user_id');
        $userId->setType(ColumnType::int);
        $create->addColumn($userId);

        $accessed = new Column();
        $accessed->setName('accessed_at');
        $accessed->setType(ColumnType::datetime);
        $create->addColumn($accessed);

        $ip = new Column();
        $ip->setName('ip_address');
        $ip->setType(ColumnType::varchar, 45);
        $create->addColumn($ip);

        $agent = new Column();
        $agent->setName('user_agent');
        $agent->setType(ColumnType::text);
        $agent->setNull(true);
        $create->addColumn($agent);

        $create->execute();
    }
};
