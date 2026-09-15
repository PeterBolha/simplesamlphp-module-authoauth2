<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authoauth2\Controller\Admin;

use SimpleSAML\Configuration;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module;
use SimpleSAML\Module\authoauth2\Codebooks\RoutesEnum;
use SimpleSAML\Module\authoauth2\Federation\ArrayLogger;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Exceptions\TrustChainException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Debug tooling for federation trust relationships, mirroring the oidc
 * module's admin testers (cacheless resolution against configured anchors).
 */
class FederationTestController
{
    use AdminTrait;

    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    private ArrayLogger $arrayLogger;

    private Federation $federationWithArrayLogger;

    public function __construct(?Configuration $config = null)
    {
        $this->config = $config ?? Configuration::getInstance();
        $this->requireAdmin();

        $this->arrayLogger = new ArrayLogger(ArrayLogger::WEIGHT_WARNING);
        // Fresh cacheless instance so every resolution actually fetches, and
        // the debug logger sees the library's warnings.
        $this->federationWithArrayLogger = new Federation(
            supportedAlgorithms: new SupportedAlgorithms(new SignatureAlgorithmBag(
                SignatureAlgorithmEnum::RS256,
                SignatureAlgorithmEnum::ES256,
                SignatureAlgorithmEnum::ES384,
                SignatureAlgorithmEnum::ES512,
            )),
            cache: null,
            logger: $this->arrayLogger,
        );
    }

    public function trustChainResolution(Request $request): Response
    {
        $federationConfig = $this->federationConfig();

        $leafEntityId = (string)($federationConfig['entityId'] ?? '');
        $trustChainBag = null;
        $resolvedMetadata = [];
        $isFormSubmitted = false;

        $configuredAnchors = $federationConfig['trustAnchors'] ?? [];
        $trustAnchorIds = is_array($configuredAnchors)
            ? array_values(array_filter($configuredAnchors, 'is_string'))
            : [];

        if ($request->isMethod(Request::METHOD_POST)) {
            $isFormSubmitted = true;

            $submittedLeaf = trim($request->request->getString('leafEntityId'));
            if ($submittedLeaf !== '') {
                $leafEntityId = $submittedLeaf;
            }

            $rawAnchors = $request->request->getString('trustAnchorIds');
            $submittedAnchors = array_values(array_filter(
                array_map('trim', preg_split('/\R/', $rawAnchors) ?: []),
                static fn(string $line): bool => $line !== '',
            ));
            if ($submittedAnchors !== []) {
                $trustAnchorIds = $submittedAnchors;
            }

            if ($leafEntityId === '' || $trustAnchorIds === []) {
                $this->arrayLogger->error('Both a leaf entity ID and at least one trust anchor ID are required.');
            } else {
                try {
                    // Guarded non-empty above; psalm can't carry that through the filters.
                    /** @psalm-suppress ArgumentTypeCoercion */
                    $trustChainBag = $this->federationWithArrayLogger->trustChainResolver()
                        ->for($leafEntityId, $trustAnchorIds);

                    foreach ($trustChainBag->getAll() as $index => $trustChain) {
                        $metadataEntries = [];
                        foreach (EntityTypesEnum::cases() as $entityTypeEnum) {
                            try {
                                $metadataEntries[$entityTypeEnum->value] =
                                    $trustChain->getResolvedMetadata($entityTypeEnum);
                            } catch (\Throwable $exception) {
                                $this->arrayLogger->error(
                                    'Metadata resolving error: ' . $exception->getMessage(),
                                    ['index' => $index, 'entityType' => $entityTypeEnum->value],
                                );
                            }
                        }
                        $resolvedMetadata[$index] = array_filter($metadataEntries);
                    }
                } catch (TrustChainException $exception) {
                    $this->arrayLogger->error('Trust chain error: ' . $exception->getMessage());
                }
            }
        }

        return $this->renderAdminPage($this->config, 'authoauth2:admin/test/trust-chain-resolution.twig', [
            'leafEntityId' => $leafEntityId,
            'trustAnchorIds' => implode("\n", $trustAnchorIds),
            'trustChainBag' => $trustChainBag,
            'resolvedMetadata' => $resolvedMetadata,
            'logMessages' => $this->arrayLogger->getEntries(),
            'isFormSubmitted' => $isFormSubmitted,
            'testUrl' => Module::getModuleURL('authoauth2/' . RoutesEnum::AdminTestTrustChainResolution->value),
        ], RoutesEnum::AdminTestTrustChainResolution);
    }

    /**
     * @return array<string, mixed>
     */
    private function federationConfig(): array
    {
        $federationConfig = Configuration::getOptionalConfig('authoauth2.php')
            ->getOptionalArray('federation', null);
        if ($federationConfig === null) {
            throw new NotFound('Federation is not configured for this module.');
        }
        return $federationConfig;
    }
}
