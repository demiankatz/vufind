<?php

/**
 * Entity model for change_tracker table
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
 * @package  Database
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:plugins:database_gateways Wiki
 */

namespace VuFind\Db\Entity;

use DateTime;
use Doctrine\ORM\Mapping as ORM;

/**
 * ChangeTracker
 *
 * @category VuFind
 * @package  Database
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:plugins:database_gateways Wiki
 *
 * @ORM\Table(name="change_tracker",
 * indexes={@ORM\Index(name="deleted_index", columns={"deleted"})}
 * )
 * @ORM\Entity
 */
class ChangeTracker implements EntityInterface
{
    /**
     * Solr core containing record.
     *
     * @var string
     *
     * @ORM\Column(name="core",
     *          type="string",
     *          length=30,
     *          nullable=false
     * )
     * @ORM\Id
     */
    protected $core;

    /**
     * Id of record within core.
     *
     * @var string
     *
     * @ORM\Column(name="id",
     *          type="string",
     *          length=120,
     *          nullable=false
     * )
     * @ORM\Id
     */
    protected $id;

    /**
     * First time added to index
     *
     * @var ?DateTime
     *
     * @ORM\Column(name="first_indexed", type="datetime", nullable=true)
     */
    protected $firstIndexed;

    /**
     * Last time changed in index.
     *
     * @var ?DateTime
     *
     * @ORM\Column(name="last_indexed", type="datetime", nullable=true)
     */
    protected $lastIndexed;

    /**
     * Last time original record was edited.
     *
     * @var ?DateTime
     *
     * @ORM\Column(name="last_record_change", type="datetime", nullable=true)
     */
    protected $lastRecordChange;

    /**
     * Time record was removed from index.
     *
     * @var ?DateTime
     *
     * @ORM\Column(name="deleted", type="datetime", nullable=true)
     */
    protected $deleted;
}
