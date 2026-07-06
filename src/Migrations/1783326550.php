<?php

use krzysztofzylka\DatabaseManager\Column;
use krzysztofzylka\DatabaseManager\CreateTable;
use krzysztofzylka\DatabaseManager\Enum\ColumnType;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Migrations\AbstractMigration;

/**
 * Create the rate limit table for DatabaseRateLimiterStorage.
 *
 * Identifiers (emails, usernames, "ip:<address>") are stored as sha256
 * hashes, timestamps as unix time integers.
 */
return new class extends AbstractMigration {

    public function run(): void
    {
        if ((new Table(Config::$rateLimitTableName))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName(Config::$rateLimitTableName);
        $table->addIdColumn();
        $table->addSimpleVarcharColumn('identifier', 64, false);
        $table->addColumn(Column::create('attempts', ColumnType::int)->setUnsigned(true)->setNull(false)->setDefault(0));
        $table->addColumn(Column::create('first_attempt', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addColumn(Column::create('last_attempt', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addColumn(Column::create('locked_until', ColumnType::bigint)->setUnsigned(true)->setNull(true));
        $table->addDateModifyColumn();
        $table->addDateCreatedColumn();
        $table->execute();
    }

};
