<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\Http\Authentication;

use Scheb\TwoFactorBundle\DependencyInjection\Factory\Security\TwoFactorFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Symfony\Component\HttpFoundation\JsonResponse;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class DefaultAuthenticationSuccessHandler implements AuthenticationSuccessHandlerInterface
{
    use TargetPathTrait;

    private const DEFAULT_OPTIONS = [
        'always_use_default_target_path' => TwoFactorFactory::DEFAULT_ALWAYS_USE_DEFAULT_TARGET_PATH,
        'default_target_path' => TwoFactorFactory::DEFAULT_TARGET_PATH,
    ];

    /**
     * @var HttpUtils
     */
    private $httpUtils;

    /**
     * @var array
     */
    private $options;

    /**
     * @var string
     */
    private $firewallName;

    private $jwt;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    public function __construct(
        HttpUtils $httpUtils,
        string $firewallName,
        array $options = [],
        $jwt = false,
        JWTTokenManagerInterface $JWTManager,
        TokenStorageInterface $tokenStorage
    ) {
        $this->httpUtils = $httpUtils;
        $this->firewallName = $firewallName;
        $this->options = array_merge(self::DEFAULT_OPTIONS, $options);
        $this->jwt = $jwt;
        $this->JWTManager = $JWTManager;
        $this->tokenStorage = $tokenStorage;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        $request->getSession()->remove(Security::AUTHENTICATION_ERROR);

        if ($this->jwt) {
            $token = $this->tokenStorage->getToken();
            $token->getUser()->set2FARoles();

            return new JsonResponse(['auth_token' => $this->JWTManager->create($token->getUser())]);
        }

        return $this->httpUtils->createRedirectResponse($request, $this->determineRedirectTargetUrl($request));
    }

    private function determineRedirectTargetUrl(Request $request): string
    {
        if ($this->options['always_use_default_target_path']) {
            return $this->options['default_target_path'];
        }

        $session = $request->getSession();
        if ($targetUrl = $this->getTargetPath($session, $this->firewallName)) {
            $this->removeTargetPath($session, $this->firewallName);

            return $targetUrl;
        }

        return $this->options['default_target_path'];
    }
}
