<?php
include(__DIR__ . '/../init.inc.php');

try {
    $db = MiniEngine::getDb();
    $sql = getQueryCreateUserTable();
    $db->exec($sql);
    $sql = getQueryCreateUserAssociateTable();
    $db->exec($sql);
    echo "Tables created successfully!\n";
} catch (Exception $e) {
    echo "Error creating table: " . $e->getMessage() . "\n";
}

function getQueryCreateUserTable()
{
    return "
        CREATE TABLE user (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            displayname TEXT,
            info TEXT
        )
    ";
}

function getQueryCreateUserAssociateTable()
{
    return "
        CREATE TABLE user_associate (
            associate_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            login_type TEXT,
            login_id TEXT,
            auth_credential TEXT,
            info TEXT
        )
    ";
}
