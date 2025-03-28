<?php
include(__DIR__ . '/../init.inc.php');

try {
    User::create('tmonk');
    UserAssociate::createViaPassword(1,
        'typingmonk',
        'password',
    );
} catch (Exception $e) {
    echo "Error creating user: " . $e->getMessage() . "\n";
}
