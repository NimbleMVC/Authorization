<?php

use krzysztofzylka\DatabaseManager\Column;
use krzysztofzylka\DatabaseManager\CreateTable;
use krzysztofzylka\DatabaseManager\Enum\ColumnType;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Migrations\AbstractMigration;

/**
 * Create the remember-me token table for RememberMeService.
 *
 * The cookie holds "selector:validator"; only the selector and a sha256
 * hash of the validator are stored.
 */
return new class extends AbstractMigration {

    public function run(): void
    {
        if ((new Table(Config::$rememberMeTableName))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName(Config::$rememberMeTableName);
        $table->addIdColumn();
        $table->addColumn(Column::create('account_id', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addSimpleVarcharColumn('selector', 24, false);
        $table->addSimpleVarcharColumn('validator_hash', 64, false);
        $table->addColumn(Column::create('date_expired', ColumnType::datetime, null)->setNull(false));
        $table->addDateModifyColumn();
        $table->addDateCreatedColumn();
        $table->execute();
    }

};
