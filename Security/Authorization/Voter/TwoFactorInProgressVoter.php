<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\Authorization\Voter;

use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Signature\LoadedJWS;

class TwoFactorInProgressVoter implements VoterInterface
{
    const IS_AUTHENTICATED_2FA_IN_PROGRESS = 'IS_AUTHENTICATED_2FA_IN_PROGRESS';

    const IS_AUTHENTICATED_FULLY = 'IS_AUTHENTICATED_FULLY';

    private $JWTManager;

    public function __construct(JWTTokenManagerInterface $JWTManager)
    {
        $this->JWTManager = $JWTManager;
    }

    public function vote(TokenInterface $token, $subject, array $attributes)
    {
        if (!($token instanceof TwoFactorTokenInterface)) {
            return VoterInterface::ACCESS_ABSTAIN;
        }

        $roles = [];
        foreach($this->JWTManager->decode($token->getAuthenticatedToken())['roles'] as $role) {
            if (in_array($role, $roles)) {
                continue;
            }
            $roles[] = $role;
        }

        foreach ($attributes as $attribute) {
            if (self::IS_AUTHENTICATED_2FA_IN_PROGcheRESS === $attribute) {
                if (in_array('ROLE_2FA', $roles)) {
                    return VoterInterface::ACCESS_DENIED;
                }

                return VoterInterface::ACCESS_GRANTED;
            }

            if (self::IS_AUTHENTICATED_FULLY === $attribute) {
                if (in_array('ROLE_2FA', $roles)) {
                    return VoterInterface::ACCESS_GRANTED;
                }

                return VoterInterface::ACCESS_ABSTAIN;
            }

            if (AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY === $attribute) {
                return VoterInterface::ACCESS_GRANTED;
            }
        }

        return VoterInterface::ACCESS_ABSTAIN;
    }
}
