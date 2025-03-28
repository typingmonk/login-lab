<?php

use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;

class AuthController extends MiniEngine_Controller
{
    public function passwordLoginAction()
    {
        $this->init_csrf();
        $csrf_token = $_POST['csrf_token'] ?? null;
        if ($csrf_token !== $this->view->csrf_token) {
            return $this->alert("Invalid CSRF token", '/');
        }

        $username = $_POST['username'] ?? null;
        $password = $_POST['password'] ?? null;

        try {
            $user = UserAssociate::authViaPassword($username, $password);
            
            if (isset($user)) {
                MiniEngine::setSession('user_id', $user->user_id);
                return $this->redirect('/');
            } else {
                return $this->alert('Invalid username or password', '/');
            }
        } catch (Exception $e) {
            return $this->alert('Login failed: ' . $e->getMessage(), '/');
        }
    }

    public function registerWebAuthnAction()
    {
        $this->init_csrf();
        $json_data = file_get_contents('php://input');
        $data = json_decode($json_data);
        $csrf_token = $data->csrf_token ?? null;

        if ($csrf_token !== $this->view->csrf_token) {
            return $this->json(['error' => 'Invalid CSRF token']);
        }

        $isLoggedIn = false;
        $user_id = MiniEngine::getSession('user_id');
        $user = null;
        if (isset($user_id)) {
            $user = User::find($user_id);
            $isLoggedIn = isset($user);
        }

        if (!$isLoggedIn) {
            return $this->json(['error' => 'Need login first']);
        }

        $login_id = $user->getUserAssociatePassword()->login_id;
        $displayname = $user->displayname;
        $public_key_credential_creation_options = self::createWebAuthnCreationOptions($login_id, $user_id, $displayname);

        return $this->json($public_key_credential_creation_options);
    }

    public function logoutAction()
    {
        MiniEngine::deleteSession('user_id');

        return $this->redirect('/');
    }

    private static function createWebAuthnCreationOptions($login_id, $user_id, $displayname)
    {
        $RP_entity = PublicKeyCredentialRpEntity::create(getenv('APP_NAME'), $_SERVER['HTTP_HOST']);
        $user_entity = PublicKeyCredentialUserEntity::create($login_id, base64_encode($user_id), $displayname);
        $challenge = random_bytes(32);

        //Addtional options
        //$pub_key_params;
        //$authenticator_selection;

        $public_key_credential_creation_options =
            PublicKeyCredentialCreationOptions::create(
                $RP_entity,
                $user_entity,
                $challenge
            );

        //TODO need to store $user_entity, $challenge and $public_key_credential_creation_options

        $attestation_statement_support_manager = AttestationStatementSupportManager::create();
        $attestation_statement_support_manager->add(NoneAttestationStatementSupport::create());
        $factory = new WebauthnSerializerFactory($attestation_statement_support_manager);
        $serializer = $factory->create();

        $json_string = $serializer->serialize(
            $public_key_credential_creation_options,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true, // Highly recommended!
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR, // Optional
            ]
        );

        return json_decode($json_string);
    }
}
