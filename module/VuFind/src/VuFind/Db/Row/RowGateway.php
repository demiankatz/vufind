<?php
/**
 * Abstract base class for DB rows.
 *
 * PHP version 7
 *
 * Copyright (C) Villanova University 2010.
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
 * @package  Db_Row
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org Main Site
 */
namespace VuFind\Db\Row;

/**
 * Abstract base class for DB rows.
 *
 * @category VuFind
 * @package  Db_Row
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org Main Site
 */
class RowGateway extends \Laminas\Db\RowGateway\RowGateway
{
    /**
     * Service plugin manager
     *
     * @var \VuFind\Db\Service\PluginManager
     */
    protected $pluginManager;

    /**
     * Retrieve primary key information.
     *
     * @return array
     */
    public function getPrimaryKeyColumn()
    {
        return $this->primaryKeyColumn;
    }

    /**
     * Set the service plugin manager.
     *
     * @param \VuFind\Db\Service\PluginManager $manager Plugin manager
     *
     * @return void
     */
    public function setDbServicePluginManager($manager)
    {
        $this->pluginManager = $manager;
    }

    /**
     * Get a database service object.
     *
     * @param string $name Name of service to retrieve
     *
     * @return \VuFind\Db\Service\AbstractService
     */
    public function getDbService(string $name)
    {
        return $this->pluginManager->get($name);
    }
}
