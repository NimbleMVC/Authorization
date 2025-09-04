<?php

use krzysztofzylka\DatabaseManager\Column;
use krzysztofzylka\DatabaseManager\CreateTable;
use krzysztofzylka\DatabaseManager\Enum\ColumnType;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Migrations\AbstractMigration;

return new class extends AbstractMigration {

    public function run(): void
    {
        $this->accounts();
        $this->account_roles();
        $this->account_permissions();
        $this->account_user_roles();
        $this->account_role_permissions();
    }

    private function accounts(): void
    {
        if ((new Table('accounts'))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName('accounts');
        $table->addIdColumn();
        $table->addUsernameColumn();
        $table->addPasswordColumn();
        $table->addEmailColumn();
        $table->addSimpleBoolColumn('active', true);
        $table->addDateModifyColumn();
        $table->addDateCreatedColumn();
        $table->execute();
    }

    private function account_roles(): void
    {
        if ((new Table('account_roles'))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName('account_roles');
        $table->addIdColumn();
        $table->addSimpleVarcharColumn('role');
        $table->addSimpleTextColumn('description');
        $table->addDateCreatedColumn();
        $table->execute();
    }

    private function account_permissions(): void
    {
        if ((new Table('account_permissions'))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName('account_permissions');
        $table->addIdColumn();
        $table->addSimpleVarcharColumn('name');
        $table->addSimpleTextColumn('description');
        $table->addSimpleVarcharColumn('group', default: 'default');
        $table->addDateCreatedColumn();
        $table->execute();
    }

    private function account_user_roles(): void
    {
        if ((new Table('account_user_roles'))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName('account_user_roles');
        $table->addIdColumn();
        $table->addColumn(Column::create('account_id', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addColumn(Column::create('role_id', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addDateCreatedColumn('date_assigned');
        $table->execute();
    }

    private function account_role_permissions(): void
    {
        if ((new Table('account_role_permissions'))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName('account_role_permissions');
        $table->addIdColumn();
        $table->addColumn(Column::create('role_id', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addColumn(Column::create('permission_id', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addDateCreatedColumn('date_assigned');
        $table->execute();
    }

};