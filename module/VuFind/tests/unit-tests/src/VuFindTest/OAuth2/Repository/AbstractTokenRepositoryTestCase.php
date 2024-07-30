<?php

/**
 * Abstract base class for OAuth2 token repository tests.
 *
 * PHP version 8
 *
 * Copyright (C) The National Library of Finland 2022.
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
 * @author   Ere Maijala <ere.maijala@helsinki.fi>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:testing:unit_tests Wiki
 */

namespace VuFindTest\OAuth2\Repository;

use PHPUnit\Framework\MockObject\MockObject;
use VuFind\Db\Entity\AccessTokenEntityInterface;
use VuFind\Db\Entity\AccessToken;
use VuFind\Db\Row\User as UserRow;
use VuFind\Db\Service\AccessTokenService;
use VuFind\Db\Service\AccessTokenServiceInterface;
use VuFind\Db\Service\UserServiceInterface;
use VuFind\Db\Table\User;
use VuFind\OAuth2\Entity\ClientEntity;
use VuFind\OAuth2\Repository\AccessTokenRepository;
use VuFind\OAuth2\Repository\AuthCodeRepository;
use VuFind\OAuth2\Repository\RefreshTokenRepository;

/**
 * Abstract base class for OAuth2 token repository tests.
 *
 * @category VuFind
 * @package  Tests
 * @author   Ere Maijala <ere.maijala@helsinki.fi>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:testing:unit_tests Wiki
 */
abstract class AbstractTokenRepositoryTestCase extends \PHPUnit\Framework\TestCase
{
    protected $accessTokenTable = [];

    /**
     * Create AccessTokenRepository with mocks.
     *
     * @return AccessTokenRepository
     */
    protected function getAccessTokenRepository()
    {
        return new AccessTokenRepository(
            $this->getOAuth2Config(),
            $this->getMockAccessTokenService(),
            $this->getMockUserService()
        );
    }

    /**
     * Create AuthCodeRepository with mocks.
     *
     * @return AuthCodeRepository
     */
    protected function getAuthCodeRepository()
    {
        return new AuthCodeRepository(
            $this->getOAuth2Config(),
            $this->getMockAccessTokenService(),
            $this->getMockUserService()
        );
    }

    /**
     * Create RefreshTokenRepository with mocks.
     *
     * @return RefreshTokenRepository
     */
    protected function getRefreshTokenRepository()
    {
        return new RefreshTokenRepository(
            $this->getOAuth2Config(),
            $this->getMockAccessTokenService(),
            $this->getMockUserService()
        );
    }

    protected function getPluginManager($setExpectation = false)
    {
        $pluginManager = $this->getMockBuilder(
            \VuFind\Db\Entity\PluginManager::class
        )->disableOriginalConstructor()
            ->getMock();
        if ($setExpectation) {
            $pluginManager->expects($this->any())->method('get')
                ->with($this->equalTo(AccessToken::class))
                ->willReturn(new AccessToken());
        }
        return $pluginManager;
    }

    /**
     * Mock entity manager.
     *
     * @return MockObject
     */
    protected function getEntityManager()
    {
        $entityManager = $this->getMockBuilder(\Doctrine\ORM\EntityManager::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['createQuery','persist','flush'])
            ->getMock();
        $query = $this->createMock(\Doctrine\ORM\Query::class);
        $entityManager->expects($this->any())->method('createQuery')->willReturn($query);
        $entityManager->expects($this->any())->method('persist');
        $entityManager->expects($this->any())->method('flush');
        return $entityManager;
    }

    /**
     * Create OAuth2 Config
     *
     * @return array
     */
    protected function getOAuth2Config(): array
    {
        return ['Server' => ['userIdentifierField' => 'id']];
    }

    /**
     * Create User table
     *
     * @return MockObject&User
     */
    protected function getMockUserTable(): User
    {
        $getByIdCallback = function (
            $id
        ): ?UserRow {
            $username = 'test';
            return $this->createUserRow(compact('id', 'username'));
        };

        $accessTokenTable = $this->getMockBuilder(User::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getById'])
            ->getMock();
        $accessTokenTable->expects($this->any())
            ->method('getById')
            ->willReturnCallback($getByIdCallback);

        return $accessTokenTable;
    }

    /**
     * Create User row
     *
     * @param array $data Row data
     *
     * @return MockObject&UserRow
     */
    protected function createUserRow(array $data): UserRow
    {
        $result = $this->getMockBuilder(UserRow::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['initialize'])
            ->getMock();
        $result->populate($data);
        return $result;
    }

    /**
     * Create Access token service
     *
     * @return MockObject&AccessTokenServiceInterface
     */
    protected function getMockAccessTokenService(): AccessTokenServiceInterface
    {
        $accessTokenTable = $this->getMockAccessTokenEntity();
        $accessTokenService = $this->getMockBuilder(AccessTokenService::class)
            ->disableOriginalConstructor()
            ->onlyMethods(
                [
                    'getByIdAndType',
                    'getNonce',
                    'storeNonce',
                ]
            )
            ->getMock();
        $accessTokenService->expects($this->any())
            ->method('getByIdAndType')
            ->willReturnCallback([$accessTokenTable, 'getByIdAndType']);
        $accessTokenService->expects($this->any())
            ->method('getNonce')
            ->willReturnCallback([$accessTokenTable, 'getNonce']);
        $accessTokenService->expects($this->any())
            ->method('storeNonce')
            ->willReturnCallback([$accessTokenTable, 'storeNonce']);
        return $accessTokenService;
    }


    /**
    * Mock Access token entity
    *
    * @return MockObject&AccessTokenEntityInterface
    */
    protected function getMockAccessTokenEntity(): AccessTokenEntityInterface
    {
        $accessTokenEntity = $this->createMock(AccessToken::class);
        $accessTokenEntity->expects($this->any())->method('getId')->willReturn((int)$this->createTokenId());
        $accessTokenEntity->expects($this->any())->method('getType')->willReturn('oauth2_access_token');
        $accessTokenEntity->expects($this->any())->method('isRevoked')->willReturn(true);
        $user = $this->createMock(\VuFind\Db\Entity\UserEntityInterface::class);
        $user->expects($this->any())->method('getId')->willReturn(1);
        $accessTokenEntity->expects($this->any())->method('getUser')->willReturn($user->getId());
        $accessTokenTable = $this->getMockBuilder(AccessToken::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getByIdAndType'])
            ->getMock();
        $accessTokenTable->expects($this->any())
            ->method('getByIdAndType')
            ->willReturn($accessTokenEntity);
        return $accessTokenEntity;
    }

    /**
     * Create User service
     *
     * @return MockObject&UserServiceInterface
     */
    protected function getMockUserService(): UserServiceInterface
    {
        $userTable = $this->getMockUserTable();
        $userService = $this->createMock(UserServiceInterface::class);
        $userService->expects($this->any())
            ->method('getUserByField')
            ->willReturnCallback(
                function ($fieldName, $fieldValue) use ($userTable) {
                    $this->assertEquals('id', $fieldName);
                    return $userTable->getById($fieldValue);
                }
            );
        return $userService;
    }

    /**
     * Create a token ID.
     *
     * Follows OAuth2 server's generateUniqueIdentifier.
     *
     * @return string
     */
    protected function createTokenId(): string
    {
        return bin2hex(random_bytes(40));
    }

    /**
     * Create an expiry datetime.
     *
     * @return \DateTimeImmutable
     */
    protected function createExpiryDateTime(): \DateTimeImmutable
    {
        return new \DateTimeImmutable(date('Y-m-d H:i:s', strtotime('now+1hour')));
    }

    /**
     * Create a client entity
     *
     * @return ClientEntity
     */
    protected function createClientEntity(): ClientEntity
    {
        return new ClientEntity(
            [
                'identifier' => 'test-client',
                'name' => 'Unit Test',
                'redirectUri' => 'https://localhost',
            ]
        );
    }
}