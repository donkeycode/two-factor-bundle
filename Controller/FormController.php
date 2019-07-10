<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Controller;

use Lexik\Bundle\JWTAuthenticationBundle\Encoder\DefaultEncoder;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTAuthenticatedEvent;
use Lexik\Bundle\JWTAuthenticationBundle\Events;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\JWTUserToken;
use Scheb\TwoFactorBundle\DependencyInjection\Factory\Security\TwoFactorFactory;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenFactoryInterface;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Scheb\TwoFactorBundle\Security\Http\ParameterBagUtils;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvents;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Exception\UnknownTwoFactorProviderException;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorProviderRegistry;
use Scheb\TwoFactorBundle\Security\TwoFactor\TwoFactorFirewallContext;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Logout\LogoutUrlGenerator;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;

class FormController
{
    private const DEFAULT_OPTIONS = [
        'auth_form_path' => TwoFactorFactory::DEFAULT_AUTH_FORM_PATH,
        'check_path' => TwoFactorFactory::DEFAULT_CHECK_PATH,
        'auth_code_parameter_name' => TwoFactorFactory::DEFAULT_AUTH_CODE_PARAMETER_NAME,
        'trusted_parameter_name' => TwoFactorFactory::DEFAULT_TRUSTED_PARAMETER_NAME,
    ];

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var TwoFactorProviderRegistry
     */
    private $providerRegistry;

    /**
     * @var TwoFactorFirewallContext
     */
    private $twoFactorFirewallContext;

    /**
     * @var LogoutUrlGenerator
     */
    private $logoutUrlGenerator;

    /**
     * @var bool
     */
    private $trustedFeatureEnabled;

    /**
     * @var TwoFactorTokenFactoryInterface
     */
    private $twoFactorTokenFactory;

    private $jwt;

    private $JWTManager;

    public function __construct(
        TokenStorageInterface $tokenStorage,
        TwoFactorProviderRegistry $providerRegistry,
        TwoFactorFirewallContext $twoFactorFirewallContext,
        LogoutUrlGenerator $logoutUrlGenerator,
        bool $trustedFeatureEnabled,
        TwoFactorTokenFactoryInterface $twoFactorTokenFactory,
        $jwt = false,
        JWTTokenManagerInterface $JWTManager
    ) {
        $this->tokenStorage = $tokenStorage;
        $this->providerRegistry = $providerRegistry;
        $this->twoFactorFirewallContext = $twoFactorFirewallContext;
        $this->trustedFeatureEnabled = $trustedFeatureEnabled;
        $this->logoutUrlGenerator = $logoutUrlGenerator;
        $this->options = self::DEFAULT_OPTIONS;
        $this->twoFactorTokenFactory = $twoFactorTokenFactory;
        $this->jwt = $jwt;
        $this->JWTManager = $JWTManager;
    }

    public function form(Request $request)
    {
        if ($this->jwt) {
            $token = $this->getTwoFactorToken();

            $authenticationException = $this->getLastAuthenticationException($request->getSession());
            if ($authenticationException === null) {
                $token->getUser()->set2FARoles();

                return new JsonResponse(['auth_token' => $this->JWTManager->create($token->getUser())]);
            } else {
                return new JsonResponse(['auth_token' => null]);
            }

        } else {
            $token = $this->getTwoFactorToken();

            $this->setPreferredProvider($request, $token);
            $providerName = $token->getCurrentTwoFactorProvider();
            $renderer = $this->providerRegistry->getProvider($providerName)->getFormRenderer();
            $templateVars = $this->getTemplateVars($request, $token);

            return $renderer->renderForm($request, $templateVars);
        }
    }

    protected function getTwoFactorToken(): TwoFactorTokenInterface
    {
        $token = $this->tokenStorage->getToken();
        if (!($token instanceof TwoFactorTokenInterface)) {
            throw new AccessDeniedException('User is not in a two-factor authentication process.');
        }

        return $token;
    }

    protected function setPreferredProvider(Request $request, TwoFactorTokenInterface $token): void
    {
        $preferredProvider = $request->get('preferProvider');
        if ($preferredProvider) {
            try {
                $token->preferTwoFactorProvider($preferredProvider);
            } catch (UnknownTwoFactorProviderException $e) {
                // Bad user input
            }
        }
    }

    protected function getTemplateVars(Request $request, TwoFactorTokenInterface $token): array
    {
        $config = $this->twoFactorFirewallContext->getFirewallConfig($token->getProviderKey());
        $pendingTwoFactorProviders = $token->getTwoFactorProviders();
        $displayTrustedOption = $this->trustedFeatureEnabled && (!$config->isMultiFactor() || 1 === count($pendingTwoFactorProviders));
        $authenticationException = $this->getLastAuthenticationException($request->getSession());

        return [
            'twoFactorProvider' => $token->getCurrentTwoFactorProvider(),
            'availableTwoFactorProviders' => $pendingTwoFactorProviders,
            'authenticationError' => $authenticationException ? $authenticationException->getMessageKey() : null,
            'authenticationErrorData' => $authenticationException ? $authenticationException->getMessageData() : null,
            'displayTrustedOption' => $displayTrustedOption,
            'authCodeParameterName' => $config->getAuthCodeParameterName(),
            'trustedParameterName' => $config->getTrustedParameterName(),
            'isCsrfProtectionEnabled' => $config->isCsrfProtectionEnabled(),
            'csrfParameterName' => $config->getCsrfParameterName(),
            'csrfTokenId' => $config->getCsrfTokenId(),
            'logoutPath' => $this->logoutUrlGenerator->getLogoutPath(),
        ];
    }

    protected function getLastAuthenticationException(SessionInterface $session): ?AuthenticationException
    {
        $authException = $session->get(Security::AUTHENTICATION_ERROR);
        if ($authException instanceof AuthenticationException) {
            $session->remove(Security::AUTHENTICATION_ERROR);

            return $authException;
        }

        return null; // The value does not come from the security component.
    }
}
