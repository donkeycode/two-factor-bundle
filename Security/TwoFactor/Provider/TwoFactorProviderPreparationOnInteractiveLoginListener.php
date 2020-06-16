<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Provider;

use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorToken;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvent;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;

class TwoFactorProviderPreparationOnInteractiveLoginListener
{
    /**
     * @var TwoFactorProviderRegistry
     */
    private $providerRegistry;

    private $jwt;

    private $loginCheckPath;

    private $container;

    public function __construct(TwoFactorProviderRegistry $providerRegistry, $jwt = false, \Psr\Container\ContainerInterface $container)
    {
        $this->providerRegistry = $providerRegistry;
        $this->jwt = $jwt;
        $this->container = $container;
        $this->loginCheckPath = $container->getParameter('scheb_two_factor.login_check_path');
    }

    public function onTwoFactorAuthenticationRequest(InteractiveLoginEvent $event)
    {
        if ($this->jwt && ($event->getRequest()->getPathInfo() == $this->loginCheckPath)) {
            $token = $event->getAuthenticationToken();
            $user = $token->getUser();

            if ($user->isEmailAuthEnabled()) {
                $this->providerRegistry->getProvider('email')->prepareAuthentication($user);
            }

            if ($user->isGoogleAuthenticatorEnabled()) {
                $this->providerRegistry->getProvider('google')->prepareAuthentication($user);
            }
        }
    }
}
