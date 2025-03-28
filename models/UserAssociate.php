<?php

class UserAssociate extends MiniEngine_Table
{
    protected $_primary_keys = 'associate_id';

    protected $_columns = [
        'associate_id' => ['type' => 'int'],
        'user_id' => ['type' => 'int'],
        'login_type' => ['type' => 'text'],
        'login_id' => ['type' => 'text'],
        'auth_credential' => ['type' => 'text'],
        'info' => ['type' => 'text'] // For storing JSON data
    ];

    protected $_relations = [
        'user' => [
            'rel' => 'has_one',
            'type' => 'User',
            'foreign_key' => 'user_id',
        ],
    ];

    public static function authViaPassword($username, $password)
    {
        $user_associate = self::search([
            'login_type' => 'password',
            'login_id' => $username,
        ])->first();

        $hash = $user_associate->auth_credential ?? '#';
        if (password_verify($password, $hash)) {
            $user = User::find($user_associate->user_id);
            return $user;
        }

        return null;
    }

    public static function createViaPassword($user_id, $login_id, $password, $info = [])
    {
        $user = User::find($user_id);
        if (is_null($user)) {
            throw new Exception("No such user with user_id: $user_id");
        }

        $user_associate_data = [
            'user_id' => $user_id,
            'login_type' => 'password',
            'login_id' => $login_id,
            'auth_credential' => password_hash('password', PASSWORD_DEFAULT) ,
            'info' => json_encode($info),
        ];

        try {
            $user_associate = self::insert($user_associate_data);
            return $user_associate;
        } catch (Exception $e) {
            error_log("Error creating user: " . $e->getMessage());
            return null;
        }
    }
}
