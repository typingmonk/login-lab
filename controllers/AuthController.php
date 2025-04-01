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
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\AuthenticatorAAssertionssertionResponse;

class AuthController extends MiniEngine_Controller
{
    public function indexAction()
    {
        $this->init_csrf();
        $csrf_token = $_POST['csrf_token'] ?? null;
        if ($csrf_token !== $this->view->csrf_token) {
            return $this->alert("Invalid CSRF token", '/');
        }

        $login_types = ['password', 'web_authn'];
        $input_auth_method = filter_input(INPUT_GET, 'type',FILTER_SANITIZE_STRING) ?? null;
        $auth_method = null;
        foreach ($login_types as $login_type) {
            if ($input_auth_method == $login_type) {
                $auth_method = $login_type;
                break;
            }
        }

        $username = $_POST['username'] ?? null;
        $login_data = UserAssociate::getLoginData($username);

        if (is_null($login_data)) {
            return $this->alert("Couldn't find your account", '/');
        }

        MiniEngine::setSession('target_user_id', $login_data->user_id);
        $this->view->username = $username;
        $this->view->auth_method = $auth_method ?? $login_data->auth_method;
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
        $json_string = MiniEngine::getSession('webauthn_credential_creation_options');
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

    public function requestWebAuthnAction()
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

        if ($isLoggedIn) {
            return $this->json(['error' => 'Already logged in']);
        }

        $target_user_id = MiniEngine::getSession('target_user_id');
        $user_associates = UserAssociate::search([
            'user_id' => $target_user_id,
            'login_type' => 'web_authn',
        ]);

        if ($user_associates->count() == 0) {
            return $this->json(['error' => 'No credential found']);
        }

        $public_key_credential_request_options = self::createWebAuthnRequestOptions($user_associates);

        return $this->json($public_key_credential_request_options);
    }

    public function verifyWebAuthnRequestAction()
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

        if ($isLoggedIn) {
            return $this->json(['error' => 'Already logged in']);
        }

        $data_str = json_encode($data);

        $serializer = self::getSerializer();
        $public_key_credential = $serializer->deserialize(
            $data_str,
            PublicKeyCredential::class,
            'json'
        );

        // check client is in Assertion step
        if (!$public_key_credential->response instanceof AuthenticatorAssertionResponse) {
            return $this->json(['error' => 'Invalid credential response type']);
        }

        // prepare ingredients for validation
        $target_user_id = MiniEngine::getSession('target_user_id');
        $user_associates = UserAssociate::search([
            'user_id' => $target_user_id,
            'login_type' => 'web_authn',
        ]);

        if ($user_associates->count() == 0) {
            return $this->json(['error' => 'No credential found']);
        }

        $public_key_credential_source = null;
        $raw_id = $public_key_credential->rawId;
        $saved_credentials = $user_associates->toArray('auth_credential');
        foreach ($saved_credentials as $saved_credential) {
            $saved_credential = $serializer->deserialize(
                $saved_credential,
                PublicKeyCredentialSource::class,
                'json'
            );
            $saved_raw_id = $saved_credential->publicKeyCredentialId;
            if ($saved_raw_id === $raw_id) {
                $public_key_credential_source = $saved_credential;
                break;
            }
        }

        if (is_null($public_key_credential_source)) {
            return $this->json(['error' => 'No credential matched']);
        }

        //get credential options back from session
        $json_string = MiniEngine::getSession('webauthn_credential_request_options');
        $public_key_credential_request_options = $serializer->deserialize(
            $json_string,
            PublicKeyCredentialRequestOptions::class,
            'json'
        );

        //get validator
        $request_CSM = self::getCeremonyStepManager('request');
        $authenticator_assertion_response_validator = AuthenticatorAssertionResponseValidator::create($request_CSM);

        //validate
        $public_key_credential_source = $authenticator_assertion_response_validator->check(
            $public_key_credential_source,
            $public_key_credential->response,
            $public_key_credential_request_options,
            $_SERVER['HTTP_HOST'],
            base64_encode($target_user_id),
        );

        MiniEngine::setSession('user_id', $target_user_id);
        return $this->json(['success' => true, 'message' => 'WebAuthn Login Success.']);
    }

    public function signupAction()
    {
        $isLoggedIn = false;
        $user_id = MiniEngine::getSession('user_id');
        $user = null;
        if (isset($user_id)) {
            $user = User::find($user_id);
            $isLoggedIn = isset($user);
        }

        if ($isLoggedIn) {
            return $this->alert('Already logged in', '/');
        }

        $this->init_csrf();
    }

    public function signupPostAction()
    {
        $this->init_csrf();
        $csrf_token = $_POST['csrf_token'] ?? null;

        if ($csrf_token !== $this->view->csrf_token) {
            return $this->alert('Invalid CSRF token', '/auth/signup');
        }

        $isLoggedIn = false;
        $user_id = MiniEngine::getSession('user_id');
        $user = null;
        if (isset($user_id)) {
            $user = User::find($user_id);
            $isLoggedIn = isset($user);
        }

        if ($isLoggedIn) {
            return $this->alert('Already logged in', '/');
        }

        $username = $_POST['username'] ?? null;
        $displayname = $_POST['displayname'] ?? null;
        $password = $_POST['password'] ?? null;
        $password_confirm = $_POST['password_confirm'] ?? null;

        if (empty($username) or empty($displayname) or empty($password) or empty($password_confirm)) {
            return $this->alert('Empty string not allowed', '/auth/signup');
        }

        if ($password != $password_confirm) {
            return $this->alert('Password confirmation failed');
        }

        $user = User::create($displayname);
        $user_associate = UserAssociate::createViaPassword($user->user_id, $username, $password);

        if (is_null($user) or is_null($user_associate)) {
            return $this->alert('Internal Error. Please try again later', '/auth/signup');
        }

        return $this->alert('Account create successed. Please login', '/');
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

        MiniEngine::setSession('webauthn_credential_creation_options', $json_string);

        return json_decode($json_string);
    }

    private static function createWebAuthnRequestOptions($user_associates)
    {
        $serializer = self::getSerializer();
        $allowed_credentials = [];
        $user_associates = $user_associates->toArray('auth_credential');
        foreach ($user_associates as $user_associate) {
            $credential = $serializer->deserialize(
                $user_associate,
                PublicKeyCredentialSource::class,
                'json'
            );
            $allowed_credentials[] = $credential->getPublicKeyCredentialDescriptor();
        }

        $public_key_credential_request_options = PublicKeyCredentialRequestOptions::create(
            random_bytes(32),
            allowCredentials: $allowed_credentials
        );

        $json_string = $serializer->serialize(
            $public_key_credential_request_options,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
            ]
        );

        MiniEngine::setSession('webauthn_credential_request_options', $json_string);

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
