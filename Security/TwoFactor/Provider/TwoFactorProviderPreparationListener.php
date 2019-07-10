<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Provider;

use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorToken;
use Scheb\TwoFactorBundle\Security\TwoFactor\Event\TwoFactorAuthenticationEvent;

class TwoFactorProviderPreparationListener
{
    /**
     * @var TwoFactorProviderRegistry
     */
    private $providerRegistry;

    private $jwt;

    public function __construct(TwoFactorProviderRegistry $providerRegistry, $jwt = false)
    {
        $this->providerRegistry = $providerRegistry;
        $this->jwt = $jwt;
    }

    public function onTwoFactorAuthenticationRequest(TwoFactorAuthenticationEvent $event)
    {
        if (!$this->jwt) {
            /** @var TwoFactorToken $token */
            $token = $event->getToken();
            $user = $token->getUser();
            $providerName = $token->getCurrentTwoFactorProvider();
            $this->providerRegistry->getProvider($providerName)->prepareAuthentication($user);
        }
    }
}
