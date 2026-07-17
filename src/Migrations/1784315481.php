<?php

use krzysztofzylka\DatabaseManager\Column;
use krzysztofzylka\DatabaseManager\CreateTable;
use krzysztofzylka\DatabaseManager\Enum\ColumnType;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Migrations\AbstractMigration;

/**
 * Store costly hashes of account recovery codes and their one-time-use state.
 */
return new class extends AbstractMigration {

    public function run(): void
    {
        if ((new Table(Config::$recoveryCodeTableName))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName(Config::$recoveryCodeTableName);
        $table->addIdColumn();
        $table->addColumn(Column::create('account_id', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addSimpleVarcharColumn('code_hash', 255, false);
        $table->addColumn(Column::create('used_at', ColumnType::datetime, null)->setNull(true));
        $table->addColumn(Column::create('expires_at', ColumnType::datetime, null)->setNull(false));
        $table->addDateModifyColumn();
        $table->addDateCreatedColumn();
        $table->execute();
    }
};
