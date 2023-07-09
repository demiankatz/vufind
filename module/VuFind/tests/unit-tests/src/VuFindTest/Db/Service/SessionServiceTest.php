<?php

/**
 * SessionService Test Class
 *
 * PHP version 8
 *
 * Copyright (C) Villanova University 2023.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @category VuFind
 * @package  Tests
 * @author   Sudharma Kellampalli <skellamp@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:testing:unit_tests Wiki
 */

namespace VuFindTest\Db\Service;

use VuFind\Db\Entity\Session;
use VuFind\Db\Service\SessionService;

/**
 * SessionService Test Class
 *
 * @category VuFind
 * @package  Tests
 * @author   Sudharma Kellampalli <skellamp@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:testing:unit_tests Wiki
 */
class SessionServiceTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Mock entity plugin manager.
     *
     * @param bool $setExpectation Flag to set the method expectations.
     *
     * @return MockObject
     */
    protected function getPluginManager($setExpectation = false)
    {
        $pluginManager = $this->getMockBuilder(
            \VuFind\Db\Entity\PluginManager::class
        )->disableOriginalConstructor()
            ->getMock();
        if ($setExpectation) {
            $pluginManager->expects($this->once())->method('get')
                ->with(Session::class)
                ->willReturn(new Session());
        }
        return $pluginManager;
    }

    /**
     * Mock entity manager.
     *
     * @param string|null $session Input query parameter
     * @param int         $count   Expectation count
     *
     * @return MockObject
     */
    protected function getEntityManager($session = null, $count = 0)
    {
        $entityManager = $this->getMockBuilder(\Doctrine\ORM\EntityManager::class)
            ->disableOriginalConstructor()
            ->getMock();
        if ($session) {
            $entityManager->expects($this->exactly($count))->method('persist');
            $entityManager->expects($this->exactly($count))->method('flush');
        }
        return $entityManager;
    }

    /**
     * Mock queryBuilder
     *
     * @param string $parameter Input query parameter
     * @param array  $result    Expected return value of getResult method.
     *
     * @return MockObject
     */
    protected function getQueryBuilder($parameter, $result)
    {
        $queryBuilder = $this->getMockBuilder(\Doctrine\ORM\QueryBuilder::class)
            ->disableOriginalConstructor()
            ->getMock();
        $queryBuilder->expects($this->once())->method('select')
            ->with('s')
            ->willReturn($queryBuilder);
        $queryBuilder->expects($this->once())->method('from')
            ->with(Session::class, 's')
            ->willReturn($queryBuilder);
        $queryBuilder->expects($this->once())->method('where')
            ->with('s.sessionId = :sid')
            ->willReturn($queryBuilder);
        $queryBuilder->expects($this->once())->method('setParameter')
            ->with('sid', $parameter)
            ->willReturn($queryBuilder);
        $query = $this->getMockBuilder(\Doctrine\ORM\AbstractQuery::class)
            ->disableOriginalConstructor()
            ->setMethods(['getResult'])
            ->getMockForAbstractClass();
        $query->expects($this->once())->method('getResult')
            ->willReturn($result);
        $queryBuilder->expects($this->once())->method('getQuery')
            ->willReturn($query);
        return $queryBuilder;
    }

    /**
     * Session service object to test.
     *
     * @param MockObject      $entityManager Mock entity manager object
     * @param MockObject      $pluginManager Mock plugin manager object
     * @param MockObject|null $session       Mock session entity object
     *
     * @return MockObject
     */
    protected function getService(
        $entityManager,
        $pluginManager,
        $session = null,
    ) {
        $serviceMock = $this->getMockBuilder(
            \VuFind\Db\Service\SessionService::class
        )
            ->setMethods(['createEntity'])
            ->setConstructorArgs([$entityManager, $pluginManager])
            ->getMock();
        if ($session) {
            $serviceMock->expects($this->once())->method('createEntity')
                ->willReturn($session);
        }
        return $serviceMock;
    }

    /**
     * Test retriving an session object from database.
     *
     * @return void
     */
    public function testGetSessionById()
    {
        $session = $this->getMockBuilder(\VuFind\Db\Entity\Session::class)
            ->disableOriginalConstructor()
            ->getMock();
        $entityManager = $this->getEntityManager($session);
        $pluginManager = $this->getPluginManager(true);
        $queryBuilder = $this->getQueryBuilder('1', [$session]);
        $entityManager->expects($this->once())->method('createQueryBuilder')
            ->willReturn($queryBuilder);
        $service = $this->getService($entityManager, $pluginManager);
        $this->assertEquals($session, $service->getBySessionId('1', false));
    }

    /**
     * Test creating a new session if no existing session is found.
     *
     * @return void
     */
    public function testCreatingSession()
    {
        $session = $this->getMockBuilder(\VuFind\Db\Entity\Session::class)
            ->disableOriginalConstructor()
            ->getMock();
        $entityManager = $this->getEntityManager($session, 1);
        $pluginManager = $this->getPluginManager(true);
        $queryBuilder = $this->getQueryBuilder('1', []);
        $entityManager->expects($this->once())->method('createQueryBuilder')
            ->willReturn($queryBuilder);
        $session->expects($this->once())->method('setSessionId')
            ->with($this->equalTo('1'))
            ->willReturn($session);
        $session->expects($this->once())->method('setCreated')
            ->with($this->anything())
            ->willReturn($session);
        $service = $this->getService($entityManager, $pluginManager, $session);
        $this->assertEquals($session, $service->getBySessionId('1', true));
    }

    /**
     * Test reading session data.
     *
     * @return void
     */
    public function testReadSession()
    {
        $session = $this->getMockBuilder(\VuFind\Db\Entity\Session::class)
            ->disableOriginalConstructor()
            ->getMock();
        $entityManager = $this->getEntityManager($session, 1);
        $pluginManager = $this->getPluginManager(true);
        $queryBuilder = $this->getQueryBuilder('1', [$session]);
        $entityManager->expects($this->once())->method('createQueryBuilder')
            ->willReturn($queryBuilder);
        $session->expects($this->once())->method('getLastUsed')
            ->willReturn(time() - 1000);
        $session->expects($this->once())->method('setLastUsed')
            ->with($this->anything());
        $session->expects($this->once())->method('getData')
            ->willReturn('foo');
        $service = $this->getService($entityManager, $pluginManager);
        $this->assertEquals('foo', $service->ReadSession('1', 10000000));
    }

    /**
     * Test storing session data.
     *
     * @return void
     */
    public function testWriteSession()
    {
        $session = $this->getMockBuilder(\VuFind\Db\Entity\Session::class)
            ->disableOriginalConstructor()
            ->getMock();
        $entityManager = $this->getEntityManager($session, 1);
        $pluginManager = $this->getPluginManager(true);
        $queryBuilder = $this->getQueryBuilder('1', [$session]);
        $entityManager->expects($this->once())->method('createQueryBuilder')
            ->willReturn($queryBuilder);
        $session->expects($this->once())->method('setLastUsed')
            ->with($this->anything())
            ->willReturn($session);
        $session->expects($this->once())->method('setData')
            ->with('foo')
            ->willReturn($session);
        $service = $this->getService($entityManager, $pluginManager);
        $this->assertEquals(true, $service->WriteSession('1', 'foo'));
    }

    /**
     * Test destroying the session.
     *
     * @return void
     */
    public function testDestroySession()
    {
        $session = $this->getMockBuilder(\VuFind\Db\Entity\Session::class)
            ->disableOriginalConstructor()
            ->getMock();
        $entityManager = $this->getEntityManager($session);
        $pluginManager = $this->getPluginManager(true);
        $queryBuilder = $this->getMockBuilder(\Doctrine\ORM\QueryBuilder::class)
            ->disableOriginalConstructor()
            ->getMock();
        $queryBuilder->expects($this->once())->method('delete')
            ->with(Session::class, 's')
            ->willReturn($queryBuilder);
        $queryBuilder->expects($this->once())->method('where')
            ->with('s.sessionId = :sid')
            ->willReturn($queryBuilder);
        $queryBuilder->expects($this->once())->method('setParameter')
            ->with('sid', 1)
            ->willReturn($queryBuilder);
        $query = $this->getMockBuilder(\Doctrine\ORM\AbstractQuery::class)
            ->disableOriginalConstructor()
            ->setMethods(['execute'])
            ->getMockForAbstractClass();
        $query->expects($this->once())->method('execute')
            ->willReturn($this->anything());
        $queryBuilder->expects($this->once())->method('getQuery')
            ->willReturn($query);
        $entityManager->expects($this->once())->method('createQueryBuilder')
            ->willReturn($queryBuilder);
        $service = $this->getService($entityManager, $pluginManager);
        $service->destroySession('1');
    }

    /**
     * Test destroying the expired sessions.
     *
     * @return void
     */
    public function testGarbageCollect()
    {
        $session = $this->getMockBuilder(\VuFind\Db\Entity\Session::class)
            ->disableOriginalConstructor()
            ->getMock();
        $entityManager = $this->getEntityManager($session);
        $pluginManager = $this->getPluginManager(true);
        $queryBuilder = $this->getMockBuilder(\Doctrine\ORM\QueryBuilder::class)
            ->disableOriginalConstructor()
            ->getMock();
        $queryBuilder->expects($this->once())->method('delete')
            ->with(Session::class, 's')
            ->willReturn($queryBuilder);
        $queryBuilder->expects($this->once())->method('where')
            ->with('s.lastUsed < used')
            ->willReturn($queryBuilder);
        $queryBuilder->expects($this->once())->method('setParameter')
            ->with('used', time() - 10000)
            ->willReturn($queryBuilder);
        $query = $this->getMockBuilder(\Doctrine\ORM\AbstractQuery::class)
            ->disableOriginalConstructor()
            ->setMethods(['execute'])
            ->getMockForAbstractClass();
        $query->expects($this->once())->method('execute')
            ->willReturn($this->anything());
        $queryBuilder->expects($this->once())->method('getQuery')
            ->willReturn($query);
        $entityManager->expects($this->once())->method('createQueryBuilder')
            ->willReturn($queryBuilder);
        $service = $this->getService($entityManager, $pluginManager);
        $service->garbageCollect(10000);
    }
}
