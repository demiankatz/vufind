<?php
/**
 * Database service for feedback.
 *
 * PHP version 7
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
 * @package  Database
 * @author   Sudharma Kellampalli <skellamp@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:plugins:database_gateways Wiki
 */
namespace VuFind\Db\Service;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Tools\Pagination\Paginator;
use VuFind\Db\Entity\Feedback;
use VuFind\Db\Entity\PluginManager as EntityPluginManager;

/**
 * Database service for feedback.
 *
 * @category VuFind
 * @package  Database
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:plugins:database_gateways Wiki
 */
class FeedbackService extends AbstractService
{
    /**
     * Constructor
     *
     * @param EntityManager       $entityManager       Doctrine ORM entity manager
     * @param EntityPluginManager $entityPluginManager VuFind entity plugin manager
     */
    public function __construct(
        EntityManager $entityManager,
        EntityPluginManager $entityPluginManager
    ) {
        parent::__construct($entityManager, $entityPluginManager);
    }

    /**
     * Create a feedback entity object.
     *
     * @return Feedback
     */
    public function createEntity(): Feedback
    {
        $class = $this->getEntityClass(Feedback::class);
        return new $class;
    }

    /**
     * Get feedback by filter
     *
     * @param string|null $formName Form name
     * @param string|null $siteUrl  Site URL
     * @param string|null $status   Current status
     * @param string|null $page     Current page
     * @param int         $limit    Limit per page
     *
     * @return Paginator
     */
    public function getFeedbackByFilter(
        $formName = null,
        $siteUrl = null,
        $status = null,
        $page = null,
        $limit = 20
    ): Paginator {
        $dql = "SELECT f, CONCAT(u.firstname, ' ', u.lastname) AS user_name, "
            . "CONCAT(m.firstname, ' ', m.lastname) AS manager_name "
            . "FROM " . $this->getEntityClass(Feedback::class) . " f "
            . "LEFT JOIN user u "
            . "LEFT JOIN updatedBy m ";
        $parameters = $dqlWhere = [];

        if (null !== $formName) {
            $dqlWhere[] = "formName = :formName";
            $parameters['formName'] = $formName;
        }
        if (null !== $siteUrl) {
            $dqlWhere[] = "siteUrl = :siteUrl";
            $parameters['siteUrl'] = $siteUrl;
        }
        if (null !== $status) {
            $dqlWhere[] = "status = :status";
            $parameters['status'] = $status;
        }
        if (!empty($dqlWhere)) {
            $dql .= ' WHERE ' . implode(' AND ', $dqlWhere);
        }
        $dql .= " ORDER BY created DESC";
        $query = $this->entityManager->createQuery($dql);
        $query->setParameters($parameters);

        if (null !== $page) {
            $query->setMaxResults($limit);
            $query->setFirstResult($limit * ($page - 1));
        }
        $paginator = new Paginator($query);
        $paginator->setUseOutputWalkers(false);
        return $paginator;
    }

    /**
     * Delete feedback by ids
     *
     * @param array $ids IDs
     *
     * @return int Count of deleted rows
     */
    public function deleteByIdArray(array $ids): int
    {
        // Do nothing if we have no IDs to delete!
        if (empty($ids)) {
            return 0;
        }
        $dql = 'DELETE FROM ' . $this->getEntityClass(Feedback::class) . ' fb '
            . ' WHERE fb.id IN (:ids)';
        $query = $this->entityManager->createQuery($dql);
        $query->setParameters(compact('ids'));
        $query->execute();
        return count($ids);
    }

    /**
     * Get values for a column
     *
     * @param string $column Column name
     *
     * @return array
     */
    public function getColumn(string $column): array
    {
        $dql = "SELECT f.id, f." . $this->mapper($column)
            . " FROM " . $this->getEntityClass(Feedback::class) . " f "
            . "ORDER BY f." . $this->mapper($column);
        $query = $this->entityManager->createQuery($dql);
        return $query->getResult();
    }

    /**
     * Update a column
     *
     * @param string $column Column name
     * @param mixed $value Column value
     * @param int $id id value
     *
     * @return bool
     */
    public function updateColumn($column, $value, $id)
    {
        $dql = "UPDATE " . $this->getEntityClass(Feedback::class) . " f "
            . "SET f." . $this->mapper($column) . " = " . $value
            . " WHERE f.id = " . $id;
        $query = $this->entityManager->createQuery($dql);
        return $query->execute();
    }

    /**
     * Db columnn name to Doctrine entity field mapper
     *
     * @param string $column Column name
     *
     * @return string
     */
    public function mapper($column)
    {
        $map = [
            'form_data' => 'formData',
            'form_name' => 'formName',
            'site_url' => 'siteUrl',
            'user_id' => 'user',
            'updated_by' => 'updatedBy',
        ];

        return $map[$column];
    }
}
