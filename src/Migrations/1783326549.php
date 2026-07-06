<?php

use krzysztofzylka\DatabaseManager\Column;
use krzysztofzylka\DatabaseManager\CreateTable;
use krzysztofzylka\DatabaseManager\Enum\ColumnType;
use krzysztofzylka\DatabaseManager\Table;
use NimblePHP\Authorization\Config;
use NimblePHP\Migrations\AbstractMigration;

/**
 * Create RBAC tables using table names from Config.
 *
 * The initial migration (1756930119) created the RBAC tables under hardcoded
 * names. This migration respects AUTHORIZATION_*_TABLE configuration; every
 * step is guarded with an exists() check, so for installations using default
 * names (already created by the initial migration) it is a no-op.
 */
return new class extends AbstractMigration {

    public function run(): void
    {
        $this->roles();
        $this->permissions();
        $this->userRoles();
        $this->rolePermissions();
    }

    private function roles(): void
    {
        if ((new Table(Config::getRoleTableName()))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName(Config::getRoleTableName());
        $table->addIdColumn();
        $table->addSimpleVarcharColumn('role');
        $table->addSimpleTextColumn('description');
        $table->addDateModifyColumn();
        $table->addDateCreatedColumn();
        $table->execute();
    }

    private function permissions(): void
    {
        if ((new Table(Config::getPermissionTableName()))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName(Config::getPermissionTableName());
        $table->addIdColumn();
        $table->addSimpleVarcharColumn('name');
        $table->addSimpleTextColumn('description');
        $table->addSimpleVarcharColumn('group', default: 'default');
        $table->addDateModifyColumn();
        $table->addDateCreatedColumn();
        $table->execute();
    }

    private function userRoles(): void
    {
        if ((new Table(Config::getUserRoleTableName()))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName(Config::getUserRoleTableName());
        $table->addIdColumn();
        $table->addColumn(Column::create('account_id', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addColumn(Column::create('role_id', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addDateModifyColumn();
        $table->addDateCreatedColumn('date_assigned');
        $table->execute();
    }

    private function rolePermissions(): void
    {
        if ((new Table(Config::getRolePermissionTableName()))->exists()) {
            return;
        }

        $table = new CreateTable();
        $table->setName(Config::getRolePermissionTableName());
        $table->addIdColumn();
        $table->addColumn(Column::create('role_id', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addColumn(Column::create('permission_id', ColumnType::bigint)->setUnsigned(true)->setNull(false));
        $table->addDateModifyColumn();
        $table->addDateCreatedColumn('date_assigned');
        $table->execute();
    }

};
