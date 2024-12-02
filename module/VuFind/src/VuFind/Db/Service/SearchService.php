<?php

/**
 * Database service for search.
 *
 * PHP version 8
 *
 * Copyright (C) Villanova University 2024.
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
 * @package  Database
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:plugins:database_gateways Wiki
 */

namespace VuFind\Db\Service;

use DateTime;
use Exception;
use VuFind\Db\Entity\Search;
use VuFind\Db\Entity\SearchEntityInterface;
use VuFind\Db\Entity\UserEntityInterface;
use VuFind\Db\Table\DbTableAwareInterface;
use VuFind\Db\Table\DbTableAwareTrait;

use function count;

/**
 * Database service for search.
 *
 * @category VuFind
 * @package  Database
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:plugins:database_gateways Wiki
 */
class SearchService extends AbstractDbService implements
    SearchServiceInterface,
    Feature\DeleteExpiredInterface,
    DbTableAwareInterface
{
    use DbTableAwareTrait;

    /**
     * Create a search entity.
     *
     * @return SearchEntityInterface
     */
    public function createEntity(): SearchEntityInterface
    {
        $class = $this->getEntityClass(Search::class);
        return new $class();
    }

    /**
     * Create a search entity containing the specified checksum, persist it to the database,
     * and return a fully populated object. Throw an exception if something goes wrong during
     * the process.
     *
     * @param int $checksum Checksum
     *
     * @return SearchEntityInterface
     * @throws Exception
     */
    public function createAndPersistEntityWithChecksum(int $checksum): SearchEntityInterface
    {
        $entity = $this->createEntity();
        $entity->setCreated(new \DateTime());
        $entity->setChecksum($checksum);

        $this->persistEntity($entity);
        $this->entityManager->flush();

        $id = $entity->getId();
        $retrieved = $this->getSearchById($id);

        if (!$retrieved) {
            throw new \Exception('Cannot find id ' . $id);
        }

        return $retrieved;
    }

    /**
     * Destroy unsaved searches belonging to the specified session/user.
     *
     * @param string                       $sessionId Session ID of current user.
     * @param UserEntityInterface|int|null $userOrId  User entity or ID of current user (optional).
     *
     * @return void
     */
    public function destroySession(string $sessionId, UserEntityInterface|int|null $userOrId = null): void
    {
        $uid = $userOrId instanceof UserEntityInterface ? $userOrId->getId() : $userOrId;
        $entityClass = $this->getEntityClass(SearchEntityInterface::class);
        $dql = 'DELETE FROM ' . $entityClass . ' s WHERE s.sessionId = :sessionId AND s.saved = 0';
        $params = ['sessionId' => $sessionId];

        if ($uid !== null) {
            $dql .= ' AND s.user = :userId';
            $params['userId'] = $uid;
        }

        $query = $this->entityManager->createQuery($dql);
        $query->setParameters($params);
        $query->execute();
    }

    /**
     * Get a SearchEntityInterface object by ID.
     *
     * @param int $id Search identifier
     *
     * @return ?SearchEntityInterface
     */
    public function getSearchById(int $id): ?SearchEntityInterface
    {
        return $this->entityManager->find($this->getEntityClass(SearchEntityInterface::class), $id);
    }

    /**
     * Get a SearchEntityInterface object by ID and owner.
     *
     * @param int                          $id        Search identifier
     * @param string                       $sessionId Session ID of current user.
     * @param UserEntityInterface|int|null $userOrId  User entity or ID of current user (optional).
     *
     * @return ?SearchEntityInterface
     */
    public function getSearchByIdAndOwner(
        int $id,
        string $sessionId,
        UserEntityInterface|int|null $userOrId
    ): ?SearchEntityInterface {
        $userId = $userOrId instanceof UserEntityInterface ? $userOrId->getId() : $userOrId;
        $entityClass = $this->getEntityClass(SearchEntityInterface::class);

        $dql = 'SELECT s FROM ' . $entityClass . ' s WHERE s.id = :id';
        $params = ['id' => $id];

        if (!empty($sessionId)) {
            $dql .= ' AND s.sessionId = :sessionId';
            $params['sessionId'] = $sessionId;
        }

        if (!empty($userId)) {
            $dql .= ' AND s.user = :userId';
            $params['userId'] = $userId;
        }

        $query = $this->entityManager->createQuery($dql);
        $query->setParameters($params);

        return $query->getOneOrNullResult();
    }

    /**
     * Get an array of rows for the specified user.
     *
     * @param ?string                      $sessionId Session ID of current user or null to ignore searches in session.
     * @param UserEntityInterface|int|null $userOrId  User entity or ID of current user (optional).
     *
     * @return SearchEntityInterface[]
     */
    public function getSearches(?string $sessionId, UserEntityInterface|int|null $userOrId = null): array
    {
        // If we don't get a session id or user id, don't return anything:
        if (null === $sessionId && null === $userOrId) {
            return [];
        }
        $uid = $userOrId instanceof UserEntityInterface ? $userOrId->getId() : $userOrId;

        $entityClass = $this->getEntityClass(SearchEntityInterface::class);
        $dql = 'SELECT s FROM ' . $entityClass . ' s WHERE ';
        $conditions = [];
        $params = [];

        if ($sessionId !== null) {
            $conditions[] = '(s.sessionId = :sessionId AND s.saved = 0)';
            $params['sessionId'] = $sessionId;
        }

        if ($uid !== null) {
            $conditions[] = 's.user = :userId';
            $params['userId'] = $uid;
        }

        if (!empty($conditions)) {
            $dql .= '(' . implode(' OR ', $conditions) . ')';
        }
        $dql .= ' ORDER BY s.created ASC';

        $query = $this->entityManager->createQuery($dql);
        $query->setParameters($params);

        return $query->getResult();
    }

    /**
     * Get scheduled searches.
     *
     * @return SearchEntityInterface[]
     */
    public function getScheduledSearches(): array
    {
        $entityClass = $this->getEntityClass(SearchEntityInterface::class);
        $dql = 'SELECT s FROM ' . $entityClass
            . ' s WHERE s.saved = 1'
            . ' AND s.notificationFrequency > 0'
            . ' ORDER BY s.user ASC';

        $query = $this->entityManager->createQuery($dql);
        return $query->getResult();
    }

    /**
     * Retrieve all searches matching the specified checksum and belonging to the user specified by session or user
     * entity/ID.
     *
     * @param int                          $checksum  Checksum to match
     * @param string                       $sessionId Current session ID
     * @param UserEntityInterface|int|null $userOrId  Entity or ID representing current user (optional).
     *
     * @return SearchEntityInterface[]
     * @throws Exception
     */
    public function getSearchesByChecksumAndOwner(
        int $checksum,
        string $sessionId,
        UserEntityInterface|int|null $userOrId = null
    ): array {
        $userId = $userOrId instanceof UserEntityInterface ? $userOrId->getId() : $userOrId;
        $dql = 'SELECT s FROM ' . $this->getEntityClass(SearchEntityInterface::class) . ' s '
            . 'WHERE s.checksum = :checksum '
            . 'AND s.sessionId = :sessionId '
            . 'AND s.saved = 0';

        $params = ['checksum' => $checksum, 'sessionId' => $sessionId];

        if (!empty($userId)) {
            $dql .= ' AND (s.userId = :userId)';
            $params['userId'] = $userId;
        }

        $query = $this->entityManager->createQuery($dql);
        $query->setParameters($params);
        return $query->getResult();
    }

    /**
     * Set invalid user_id values in the table to null; return count of affected rows.
     *
     * @return int
     */
    public function cleanUpInvalidUserIds(): int
    {
        $dql = 'SELECT u.id FROM ' . $this->getEntityClass(UserEntityInterface::class) . ' u';
        $query = $this->entityManager->createQuery($dql);
        $validUserIds = $query->getResult();

        // Extract just the IDs for comparison
        $validUserIds = array_map(fn ($user) => $user['id'], $validUserIds);

        if (empty($validUserIds)) {
            return 0;
        }

        $dql = 'SELECT s FROM ' . $this->getEntityClass(SearchEntityInterface::class) . ' s '
             . 'WHERE s.userId IS NOT NULL '
             . 'AND s.userId NOT IN (:validUserIds)';
        $query = $this->entityManager->createQuery($dql);
        $query->setParameter('validUserIds', $validUserIds);
        $invalidSearches = $query->getResult();

        $count = count($invalidSearches);
        if ($count > 0) {
            // Update invalid records to set userId to null
            $dql = 'UPDATE ' . $this->getEntityClass(SearchEntityInterface::class) . ' s '
                 . 'SET s.userId = NULL '
                 . 'WHERE s.userId NOT IN (:validUserIds)';
            $updateQuery = $this->entityManager->createQuery($dql);
            $updateQuery->setParameter('validUserIds', $validUserIds);
            $updateQuery->execute();
        }
        return $count;
    }

    /**
     * Get saved searches with missing checksums (used for cleaning up legacy data).
     *
     * @return SearchEntityInterface[]
     */
    public function getSavedSearchesWithMissingChecksums(): array
    {
        $dql = 'SELECT s FROM ' . $this->getEntityClass(SearchEntityInterface::class) . ' s '
        . 'WHERE s.checksum IS NULL AND s.saved = 1';

        $query = $this->entityManager->createQuery($dql);
        return $query->getResult();
    }

    /**
     * Delete expired records. Allows setting a limit so that rows can be deleted in small batches.
     *
     * @param DateTime $dateLimit Date threshold of an "expired" record.
     * @param ?int     $limit     Maximum number of rows to delete or null for no limit.
     *
     * @return int Number of rows deleted
     */
    public function deleteExpired(DateTime $dateLimit, ?int $limit = null): int
    {
        $subQueryBuilder = $this->entityManager->createQueryBuilder();
        $subQueryBuilder->select('s.id')
            ->from($this->getEntityClass(SearchEntityInterface::class), 's')
            ->where('s.created < :dateLimit')
            ->setParameter('dateLimit', $dateLimit->format('Y-m-d H:i:s'));

        if ($limit) {
            $subQueryBuilder->setMaxResults($limit);
        }
        $queryBuilder = $this->entityManager->createQueryBuilder();
        $queryBuilder->delete($this->getEntityClass(SearchEntityInterface::class), 's')
            ->where('s.id IN (:searches)')
            ->setParameter('searches', $subQueryBuilder->getQuery()->getResult());

        return $queryBuilder->getQuery()->execute();
    }
}
