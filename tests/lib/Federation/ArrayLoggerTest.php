<?php

declare(strict_types=1);

namespace Test\SimpleSAML\Federation;

use PHPUnit\Framework\TestCase;
use Psr\Log\InvalidArgumentException;
use SimpleSAML\Module\authoauth2\Federation\ArrayLogger;

class ArrayLoggerTest extends TestCase
{
    public function testCollectsAtOrAboveWeight(): void
    {
        $logger = new ArrayLogger(ArrayLogger::WEIGHT_WARNING);
        $logger->warning('a warning');
        $logger->error('an error');
        $logger->debug('a debug line');
        $logger->info('an info line');

        $entries = $logger->getEntries();
        $this->assertCount(2, $entries);
        $this->assertStringContainsString('WARNING a warning', $entries[0]);
        $this->assertStringContainsString('ERROR an error', $entries[1]);
    }

    public function testDefaultWeightCollectsEverything(): void
    {
        $logger = new ArrayLogger();
        $logger->debug('dbg');
        $this->assertCount(1, $logger->getEntries());
    }

    public function testContextIsAppended(): void
    {
        $logger = new ArrayLogger();
        $logger->error('boom', ['index' => 3]);
        $this->assertStringContainsString("Context: array (\n  'index' => 3,\n)", $logger->getEntries()[0]);
    }

    public function testLogDispatchesByLevel(): void
    {
        $logger = new ArrayLogger(ArrayLogger::WEIGHT_ERROR);
        $logger->log('error', 'via log method');
        $logger->log('warning', 'dropped');
        $this->assertCount(1, $logger->getEntries());
        $this->assertStringContainsString('ERROR via log method', $logger->getEntries()[0]);
    }

    public function testUnknownLevelRejected(): void
    {
        $logger = new ArrayLogger();
        $this->expectException(InvalidArgumentException::class);
        $logger->log('nope', 'message');
    }
}
