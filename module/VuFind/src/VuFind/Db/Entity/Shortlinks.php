<?php

/**
 * Entity model for shortlinks table
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
 * Shortlinks
 *
 * @category VuFind
 * @package  Database
 * @author   Demian Katz <demian.katz@villanova.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     https://vufind.org/wiki/development:plugins:database_gateways Wiki
 *
 * @ORM\Entity
 * @ORM\Table(name="shortlinks",
 *          uniqueConstraints={@ORM\UniqueConstraint(name="shortlinks_hash_IDX",
 *                          columns={"hash"})}
 * )
 */
class Shortlinks implements ShortlinksEntityInterface
{
    /**
     * Unique ID.
     *
     * @var int
     *
     * @ORM\Column(name="id",
     *          type="integer",
     *          nullable=false
     * )
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="IDENTITY")
     */
    protected $id;

    /**
     * Shortened URL.
     *
     * @var string
     *
     * @ORM\Column(name="path", type="text", length=16777215, nullable=false)
     */
    protected $path;

    /**
     * Shortlinks hash.
     *
     * @var ?string
     *
     * @ORM\Column(name="hash", type="string", length=32, nullable=true)
     */
    protected $hash;

    /**
     * Creation timestamp.
     *
     * @var \DateTime
     *
     * @ORM\Column(name="created",
     *          type="datetime",
     *          nullable=false,
     *          options={"default"="CURRENT_TIMESTAMP"}
     * )
     */
    protected $created = 'CURRENT_TIMESTAMP';

    /**
     * Id getter
     *
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * Shortlinks hash setter
     *
     * @param ?string $hash Shortlinks hash.
     *
     * @return Shortlinks
     */
    public function setHash(?string $hash): Shortlinks
    {
        $this->hash = $hash;
        return $this;
    }

    /**
     * Hash getter
     *
     * @return ?string
     */
    public function getHash(): ?string
    {
        return $this->hash;
    }

    /**
     * Shortened URL setter
     *
     * @param string $path Shortened URL.
     *
     * @return Shortlinks
     */
    public function setPath(string $path): Shortlinks
    {
        $this->path = $path;
        return $this;
    }

    /**
     * Path getter
     *
     * @return string
     */
    public function getPath(): string
    {
        return $this->path;
    }

    /**
     * Created setter.
     *
     * @param DateTime $dateTime Created date
     *
     * @return Shortlinks
     */
    public function setCreated(DateTime $dateTime): Shortlinks
    {
        $this->created = $dateTime;
        return $this;
    }

    /**
     * Created getter
     *
     * @return DateTime
     */
    public function getCreated(): DateTime
    {
        return $this->created;
    }
}
