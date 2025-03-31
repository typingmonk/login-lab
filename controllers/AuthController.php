<?php

use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\AuthenticatorAttestationResponseValidator;

class AuthController extends MiniEngine_Controller
{
    public function indexAction()
    {
        $this->init_csrf();
        $csrf_token = $_POST['csrf_token'] ?? null;
        if ($csrf_token !== $this->view->csrf_token) {
            return $this->alert("Invalid CSRF token", '/');
        }

        $username = $_POST['username'] ?? null;
        $login_data = UserAssociate::getLoginData($username);

        if (is_null($login_data)) {
            return $this->alert("Couldn't find your account", '/');
        }

        MiniEngine::setSession('target_user_id', $login_data->user_id);
        $this->view->auth_method = $login_data->auth_method;
    }

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

    public function verifyWebAuthnRegistrationAction()
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

        $data_str = json_encode($data);

        $attestation_statement_support_manager = self::getAttestationStatementSupportManager();
        $serializer = self::getSerializer($attestation_statement_support_manager);

        $public_key_credential = $serializer->deserialize(
            $data_str,
            PublicKeyCredential::class,
            'json'
        );

        //check client is in attestation step
        if (!$public_key_credential->response instanceof AuthenticatorAttestationResponse) {
            return $this->json(['error' => 'Invalid credential response type']);
        }

        //get validator
        $creation_CSM = self::getCeremonyStepManager('creation');
        $authenticator_attestation_response_validator = AuthenticatorAttestationResponseValidator::create($creation_CSM);

        //get credential options back from session
        $json_string = MiniEngine::getSession('webauthn_credential_options');
        $public_key_credential_creation_options = $serializer->deserialize(
            $json_string,
            PublicKeyCredentialCreationOptions::class,
            'json'
        );

        //vaildate
        $public_key_credential_source = $authenticator_attestation_response_validator->check(
            $public_key_credential->response,
            $public_key_credential_creation_options,
            $_SERVER['HTTP_HOST'],
        );

        $public_key_credential_source_json_string = $serializer->serialize(
            $public_key_credential_source,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
            ]
        );

        $user_associate = UserAssociate::createViaWebAuthn($user_id, $public_key_credential_source_json_string);
        return $this->json(['success' => true, 'message' => 'WebAuthn Registration Success.']);
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
                rp: $RP_entity,
                user: $user_entity,
                challenge: $challenge,
                timeout: 90000
            );

        MiniEngine::setSession('webauthn_user_entity', serialize($user_entity));

        $serializer = self::getSerializer();

        $json_string = $serializer->serialize(
            $public_key_credential_creation_options,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
            ]
        );

        MiniEngine::setSession('webauthn_credential_options', $json_string);

        return json_decode($json_string);
    }

    private static function getAttestationStatementSupportManager()
    {
        $attestation_statement_support_manager = AttestationStatementSupportManager::create();
        $attestation_statement_support_manager->add(NoneAttestationStatementSupport::create());
        return $attestation_statement_support_manager;
    }

    private static function getSerializer($attestation_statement_support_manager = null)
    {
        if (is_null($attestation_statement_support_manager)) {
            $attestation_statement_support_manager = self::getAttestationStatementSupportManager();
        }
        $factory = new WebauthnSerializerFactory($attestation_statement_support_manager);
        $serializer = $factory->create();

        return $serializer;
    }

    private static function getCeremonyStepManager($ceremony_type = 'creation') 
    {
        $csmFactory = new CeremonyStepManagerFactory();

        if ($ceremony_type == 'creation') {
            return  $csmFactory->creationCeremony();
        } else {
            return  $csmFactory->requestCeremony();
        }
    }
}
