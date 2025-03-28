<?php

class UserRow extends MiniEngine_Table_Row
{
    public function getUserAssociatePassword()
    {
        return $this->user_associates->search(['login_type' => 'password'])->first();
    }
}
