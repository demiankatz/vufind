<?php

/**
 * List view helper
 *
 * PHP version 8
 *
 * Copyright (C) Villanova University 2010-2023.
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
 * @package  View_Helpers
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development Wiki
 */

namespace VuFind\View\Helper\Root;

use Laminas\Session\Container;
use Laminas\View\Helper\AbstractHelper;
use VuFind\Db\Service\UserListService as ListService;

/**
 * List view helper
 *
 * @category VuFind
 * @package  View_Helpers
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development Wiki
 */
class UserList extends AbstractHelper
{
    /**
     * List mode (enabled or disabled)
     *
     * @var string
     */
    protected $mode;

    /**
     * Session container for last list information.
     *
     * @var Container
     */
    protected $session;

    /**
     * UserList database service
     *
     * @var ListService
     */
    protected $listService;

    /**
     * Constructor
     *
     * @param Container   $session     Session container (must use same namespace as
     *                                 container provided to
     *                                 \VuFind\Db\Table\UserList)
     * @param string      $mode        List mode (enabled or disabled)
     * @param ListService $listService UserList database service
     */
    public function __construct(Container $session, $mode, ListService $listService)
    {
        $this->mode = $mode;
        $this->session = $session;
        $this->listService = $listService;
    }

    /**
     * Get mode
     *
     * @return string
     */
    public function getMode()
    {
        return $this->mode;
    }

    /**
     * Retrieve the ID of the last list that was accessed, if any.
     *
     * @return mixed User_list ID (if set) or null (if not available).
     */
    public function lastUsed()
    {
        return $this->session->lastUsed ?? null;
    }

    /**
     * Proxy to the userList method of UserListService
     *
     * @param User|int $user Id of the user owning the list.
     *
     * @return array
     */
    public function getLists($user)
    {
        return $this->listService->getLists($user);
    }
}
